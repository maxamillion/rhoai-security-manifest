"""HTTP debugging utilities for REST API call logging."""

import json
import time
from typing import Optional

import httpx

from .logging import get_logger

logger = get_logger("http_debug")


def sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
    """Sanitize sensitive headers for logging.

    Args:
        headers: Original headers dictionary

    Returns:
        Sanitized headers with sensitive values masked
    """
    sanitized = headers.copy()
    sensitive_headers = {
        "authorization",
        "x-api-key",
        "x-auth-token",
        "cookie",
        "x-forwarded-for",
        "x-real-ip",
        "proxy-authorization",
    }

    for key in list(sanitized.keys()):
        if key.lower() in sensitive_headers:
            sanitized[key] = "[REDACTED]"

    return sanitized


def truncate_content(content: str, max_length: int = 1000) -> str:
    """Truncate content for logging with indication if truncated.

    Args:
        content: Content to potentially truncate
        max_length: Maximum length before truncation

    Returns:
        Truncated content with indication if truncated
    """
    if len(content) <= max_length:
        return content

    return content[:max_length] + f"... (truncated, total length: {len(content)} chars)"


def format_json_content(content: str) -> str:
    """Format JSON content for better readability in logs.

    Args:
        content: Raw content string

    Returns:
        Formatted JSON string or original content if not valid JSON
    """
    try:
        # Try to parse and re-format JSON for better readability
        parsed = json.loads(content)
        return json.dumps(parsed, indent=2, ensure_ascii=False)
    except (json.JSONDecodeError, TypeError):
        # Not valid JSON, return as-is
        return content


def log_http_request(
    method: str,
    url: str,
    params: Optional[dict] = None,
    headers: Optional[dict[str, str]] = None,
    content: Optional[str] = None,
) -> None:
    """Log HTTP request details in debug mode.

    Args:
        method: HTTP method (GET, POST, etc.)
        url: Full request URL
        params: Query parameters
        headers: Request headers
        content: Request body content
    """
    if not logger.isEnabledFor(10):  # DEBUG level is 10
        return

    logger.debug("=== HTTP Request ===")
    logger.debug(f"Method: {method}")
    logger.debug(f"URL: {url}")

    if params:
        logger.debug(f"Query Parameters: {params}")

    if headers:
        sanitized_headers = sanitize_headers(headers)
        logger.debug(f"Request Headers: {sanitized_headers}")

    if content:
        formatted_content = format_json_content(content)
        truncated_content = truncate_content(formatted_content)
        logger.debug(f"Request Body: {truncated_content}")
    else:
        logger.debug("Request Body: <none>")


def log_http_response(
    response: httpx.Response,
    duration: float,
    error: Optional[Exception] = None,
    suppress_expected_404: bool = False,
) -> None:
    """Log HTTP response details in debug mode.

    Args:
        response: HTTP response object
        duration: Request duration in seconds
        error: Exception if request failed
        suppress_expected_404: Whether to suppress logging for expected 404 errors
    """
    if not logger.isEnabledFor(10):  # DEBUG level is 10
        return

    # Check if this is an expected 404 that should be suppressed
    if suppress_expected_404 and error and hasattr(error, "response"):
        if error.response is not None and error.response.status_code == 404:
            logger.debug(f"Expected 404 (endpoint exploration): {error}")
            return

    logger.debug("=== HTTP Response ===")

    if error:
        # Reduce verbosity for 404 errors during endpoint exploration
        if (
            hasattr(error, "response")
            and error.response is not None
            and error.response.status_code == 404
        ):
            logger.debug("Status: 404 Not Found (endpoint exploration)")
            logger.debug(f"Duration: {duration:.3f}s")
        else:
            logger.debug(f"Status: ERROR - {error}")
            logger.debug(f"Duration: {duration:.3f}s")

            # Log response details if available
            if hasattr(error, "response") and error.response is not None:
                logger.debug(f"Error Status Code: {error.response.status_code}")
                try:
                    error_content = error.response.text
                    if error_content:
                        formatted_content = format_json_content(error_content)
                        truncated_content = truncate_content(formatted_content)
                        logger.debug(f"Error Response Body: {truncated_content}")
                except Exception:
                    logger.debug("Error Response Body: <could not read>")
    else:
        logger.debug(f"Status: {response.status_code} {response.reason_phrase}")
        logger.debug(f"Duration: {duration:.3f}s")

        # Log response headers (sanitized)
        response_headers = dict(response.headers)
        sanitized_headers = sanitize_headers(response_headers)
        logger.debug(f"Response Headers: {sanitized_headers}")

        # Log response body
        try:
            response_text = response.text
            if response_text:
                formatted_content = format_json_content(response_text)
                truncated_content = truncate_content(formatted_content)
                logger.debug(f"Response Body: {truncated_content}")
            else:
                logger.debug("Response Body: <empty>")
        except Exception as e:
            logger.debug(f"Response Body: <could not read: {e}>")

    logger.debug("=== End HTTP Response ===")


def debug_http_request(
    method: str,
    url: str,
    params: Optional[dict] = None,
    headers: Optional[dict[str, str]] = None,
    content: Optional[str] = None,
    suppress_expected_404: bool = False,
):
    """Context manager for debugging HTTP requests.

    Args:
        method: HTTP method
        url: Request URL
        params: Query parameters
        headers: Request headers
        content: Request body
        suppress_expected_404: Whether to suppress logging for expected 404 errors

    Returns:
        Context manager that logs request start and provides callback for response
    """

    class HTTPDebugContext:
        def __init__(self):
            self.start_time = None

        def __enter__(self):
            self.start_time = time.time()
            log_http_request(method, url, params, headers, content)
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            if exc_val:
                duration = time.time() - self.start_time
                log_http_response(None, duration, exc_val, suppress_expected_404)

        def log_response(self, response: httpx.Response):
            """Log successful response."""
            duration = time.time() - self.start_time
            log_http_response(response, duration)

    return HTTPDebugContext()
