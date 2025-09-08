#!/usr/bin/env python3

import requests
import json
import logging
import time
from typing import List, Dict, Optional, Any
from urllib.parse import urljoin, quote
import re


class AtlasClient:
    """Client for Atlas Release API vulnerability analysis."""

    def __init__(
        self,
        base_url: str = "https://atlas.release.devshift.net",
        timeout: int = 30,
        max_retries: int = 3,
    ):
        """Initialize Atlas API client.

        Args:
            base_url: Atlas API base URL
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = requests.Session()
        self.logger = logging.getLogger(__name__)

        # Set default headers
        self.session.headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "RHOAI-Security-Analyzer/1.0",
            }
        )

    def _make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make HTTP request with retry logic.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path
            **kwargs: Additional request arguments

        Returns:
            Response object

        Raises:
            requests.RequestException: On request failure after retries
        """
        url = urljoin(self.base_url, endpoint)

        for attempt in range(self.max_retries + 1):
            try:
                self.logger.debug(
                    f"Making {method} request to {url} (attempt {attempt + 1})"
                )

                response = self.session.request(
                    method=method, url=url, timeout=self.timeout, **kwargs
                )

                # Raise for HTTP errors
                response.raise_for_status()
                return response

            except requests.exceptions.RequestException as e:
                if attempt == self.max_retries:
                    self.logger.error(
                        f"Request failed after {self.max_retries + 1} attempts: {e}"
                    )
                    raise

                # Exponential backoff with jitter
                wait_time = (2**attempt) + (time.time() % 1)
                self.logger.warning(
                    f"Request failed (attempt {attempt + 1}), retrying in {wait_time:.2f}s: {e}"
                )
                time.sleep(wait_time)

    def analyze_vulnerabilities(self, purls: List[str]) -> Dict[str, Any]:
        """Analyze vulnerabilities for a list of Package URLs.

        Args:
            purls: List of Package URLs to analyze

        Returns:
            Dictionary containing vulnerability analysis results

        Raises:
            requests.RequestException: On API request failure
            ValueError: On invalid input or response
        """
        if not purls:
            raise ValueError("PURL list cannot be empty")

        if not isinstance(purls, list):
            raise ValueError("PURLs must be provided as a list")

        # Validate PURLs format
        invalid_purls = [purl for purl in purls if not self._is_valid_purl(purl)]
        if invalid_purls:
            self.logger.warning(
                f"Found {len(invalid_purls)} invalid PURLs: {invalid_purls[:3]}..."
            )

        self.logger.info(f"Analyzing vulnerabilities for {len(purls)} PURLs")

        # Prepare request payload
        payload = {"purls": purls}

        # Make API request
        response = self._make_request(
            method="POST", endpoint="/api/v2/vulnerability/analyze", json=payload
        )

        try:
            result = response.json()
            self.logger.info(f"Successfully analyzed {len(purls)} PURLs")
            return result
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse API response as JSON: {e}")
            raise ValueError(f"Invalid JSON response from Atlas API: {e}")

    def get_vulnerability_details(self, vulnerability_id: str) -> Dict[str, Any]:
        """Get detailed information for a specific vulnerability.

        Args:
            vulnerability_id: Vulnerability identifier

        Returns:
            Dictionary containing vulnerability details
        """
        if not vulnerability_id:
            raise ValueError("Vulnerability ID cannot be empty")

        self.logger.debug(f"Fetching details for vulnerability: {vulnerability_id}")

        # URL encode the vulnerability ID to handle special characters
        encoded_id = quote(vulnerability_id, safe="")

        response = self._make_request(
            method="GET", endpoint=f"/api/v2/vulnerability/{encoded_id}"
        )

        try:
            result = response.json()
            self.logger.debug(
                f"Successfully fetched details for vulnerability {vulnerability_id}"
            )
            return result
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse vulnerability details as JSON: {e}")
            raise ValueError(
                f"Invalid JSON response for vulnerability {vulnerability_id}: {e}"
            )

    def search_vulnerabilities(
        self, query: str = "", limit: int = 100, offset: int = 0, **filters
    ) -> Dict[str, Any]:
        """Search vulnerabilities with advanced filtering.

        Args:
            query: Search query string
            limit: Maximum number of results to return
            offset: Number of results to skip
            **filters: Additional filter parameters

        Returns:
            Dictionary containing search results
        """
        params = {"limit": limit, "offset": offset}

        if query:
            params["q"] = query

        # Add any additional filters
        params.update(filters)

        self.logger.debug(f"Searching vulnerabilities with params: {params}")

        response = self._make_request(
            method="GET", endpoint="/api/v2/vulnerability", params=params
        )

        try:
            result = response.json()
            self.logger.debug(f"Found {len(result.get('data', []))} vulnerabilities")
            return result
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse search results as JSON: {e}")
            raise ValueError(f"Invalid JSON response from vulnerability search: {e}")

    def _is_valid_purl(self, purl: str) -> bool:
        """Validate Package URL format.

        Args:
            purl: Package URL to validate

        Returns:
            True if PURL is valid, False otherwise
        """
        if not isinstance(purl, str) or not purl:
            return False

        # Basic PURL format validation: pkg:type/namespace/name@version
        purl_pattern = (
            r"^pkg:[a-zA-Z0-9\-\.]+(/[^@]+)?(/[^@]+)?(@[^#?]+)?(\?[^#]+)?(#.*)?$"
        )
        return bool(re.match(purl_pattern, purl))

    def test_connection(self) -> bool:
        """Test connection to Atlas API.

        Returns:
            True if connection successful, False otherwise
        """
        try:
            self.logger.info("Testing Atlas API connection...")

            # Try a simple search request with minimal parameters
            response = self._make_request(
                method="GET", endpoint="/api/v2/vulnerability", params={"limit": 1}
            )

            self.logger.info("Atlas API connection test successful")
            return True

        except Exception as e:
            self.logger.error(f"Atlas API connection test failed: {e}")
            return False


def generate_container_purl(
    registry: str, repository: str, tag: str = "", digest: str = ""
) -> str:
    """Generate Package URL for a container image.

    Args:
        registry: Container registry hostname
        repository: Repository name
        tag: Image tag (optional)
        digest: Image digest (optional)

    Returns:
        Package URL string

    Raises:
        ValueError: On invalid input parameters
    """
    if not registry or not repository:
        raise ValueError("Registry and repository are required")

    # Clean up inputs
    registry = registry.strip().lower()
    repository = repository.strip()

    # Remove protocol if present
    if registry.startswith(("http://", "https://")):
        registry = registry.split("://", 1)[1]

    # Build PURL
    purl = f"pkg:oci/{repository}"

    # Add version (prefer digest over tag)
    if digest:
        # Clean up digest format
        if digest.startswith("sha256:"):
            digest = digest[7:]
        purl += f"@sha256:{digest}"
    elif tag:
        purl += f"@{tag}"

    # Add registry as qualifier
    purl += f"?repository_url={registry}"

    return purl


def generate_rpm_purl(
    name: str, version: str = "", epoch: str = "", release: str = "", arch: str = ""
) -> str:
    """Generate Package URL for an RPM package.

    Args:
        name: Package name
        version: Package version
        epoch: Package epoch
        release: Package release
        arch: Package architecture

    Returns:
        Package URL string

    Raises:
        ValueError: On invalid input parameters
    """
    if not name:
        raise ValueError("Package name is required")

    # Build PURL
    purl = f"pkg:rpm/redhat/{name.strip()}"

    # Add version if provided
    if version:
        version_str = version.strip()
        if epoch:
            version_str = f"{epoch.strip()}:{version_str}"
        if release:
            version_str = f"{version_str}-{release.strip()}"
        purl += f"@{version_str}"

    # Add architecture as qualifier
    if arch:
        purl += f"?arch={arch.strip()}"

    return purl


def extract_purls_from_image_data(image_data: Dict[str, Any]) -> List[str]:
    """Extract Package URLs from RHOAI image data.

    Args:
        image_data: Image data dictionary from Pyxis API

    Returns:
        List of Package URLs for the image
    """
    purls = []

    try:
        # Extract container image PURL
        if image_data.get("repositories") and len(image_data["repositories"]) > 0:
            repo_info = image_data["repositories"][0]
            registry = repo_info.get("registry", "")
            repository = repo_info.get("repository", "")

            # Get image digest if available
            image_id = image_data.get("image_id", "")
            digest = ""
            if image_id and image_id.startswith("sha256:"):
                digest = image_id[7:]  # Remove 'sha256:' prefix

            # Get tags
            tags = repo_info.get("tags", [])
            tag = ""
            if tags and len(tags) > 0:
                tag = tags[0].get("name", "")

            if registry and repository:
                container_purl = generate_container_purl(
                    registry=registry, repository=repository, tag=tag, digest=digest
                )
                purls.append(container_purl)

        # TODO: Add extraction of individual package PURLs from SBOM data
        # This would require analyzing the SBOM to identify individual packages
        # within the container image

    except Exception as e:
        logging.getLogger(__name__).warning(
            f"Failed to extract PURLs from image data: {e}"
        )

    return purls


if __name__ == "__main__":
    # Basic test functionality
    import sys

    logging.basicConfig(level=logging.INFO)

    client = AtlasClient()

    if client.test_connection():
        print("✓ Atlas API connection successful")

        # Test PURL generation
        test_purl = generate_container_purl(
            registry="registry.redhat.io",
            repository="ubi8/ubi",
            tag="latest",
            digest="abcd1234",
        )
        print(f"✓ Generated test PURL: {test_purl}")

        # Test vulnerability analysis with a simple PURL
        try:
            result = client.analyze_vulnerabilities([test_purl])
            print(f"✓ Vulnerability analysis successful: {len(result)} results")
        except Exception as e:
            print(f"⚠ Vulnerability analysis test failed: {e}")

    else:
        print("✗ Atlas API connection failed")
        sys.exit(1)
