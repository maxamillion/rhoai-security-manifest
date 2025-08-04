"""Red Hat Container Catalog API client."""

import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import httpx
from pydantic import BaseModel, Field

from ..utils.logging import get_logger
from ..utils.http_debug import debug_http_request

logger = get_logger("api.container_catalog")


class ContainerImage(BaseModel):
    """Container image metadata from catalog."""

    name: str
    registry_url: str
    digest: str
    tag: str
    created_at: datetime
    architecture: str = "x86_64"
    size_bytes: Optional[int] = None
    layers: List[str] = Field(default_factory=list)
    labels: Dict[str, str] = Field(default_factory=dict)


class CatalogSearchResult(BaseModel):
    """Search result from container catalog."""

    total: int
    page: int
    page_size: int
    images: List[ContainerImage]


class ContainerCatalogClient:
    """Client for Red Hat Container Catalog API."""

    def __init__(
        self,
        base_url: str = "https://catalog.redhat.com/api/containers/v1/",
        timeout: int = 30,
        max_retries: int = 3,
        max_concurrent: int = 10,
    ):
        """Initialize the catalog client.

        Args:
            base_url: Base URL for the Container Catalog API
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            max_concurrent: Maximum concurrent requests
        """
        self.base_url = base_url.rstrip("/") + "/"
        self.timeout = timeout
        self.max_retries = max_retries
        self.max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)

        # Track failed endpoints to avoid repeated 404s
        self._failed_endpoints = set()
        self._working_endpoints = set()

        # Configure HTTP client
        self._client = httpx.AsyncClient(
            timeout=timeout, limits=httpx.Limits(max_connections=max_concurrent * 2)
        )

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self._client.aclose()

    async def close(self):
        """Close the HTTP client."""
        await self._client.aclose()

    async def _try_endpoints_smartly(
        self, endpoint_patterns: List[str], **format_args
    ) -> Optional[Dict[str, Any]]:
        """Try multiple endpoints intelligently, skipping known failed ones.

        Args:
            endpoint_patterns: List of endpoint URL patterns to try
            **format_args: Arguments to format into the endpoint patterns

        Returns:
            Response data from first successful endpoint, or None if all fail
        """
        successful_data = None

        # First, try any endpoints we know work
        working_endpoints = [
            ep
            for ep in endpoint_patterns
            if ep.format(**format_args) in self._working_endpoints
        ]

        # Then try unknown endpoints
        unknown_endpoints = [
            ep
            for ep in endpoint_patterns
            if ep.format(**format_args) not in self._working_endpoints
            and ep.format(**format_args) not in self._failed_endpoints
        ]

        # Finally, try failed endpoints as a last resort (API might have been fixed)
        failed_endpoints = [
            ep
            for ep in endpoint_patterns
            if ep.format(**format_args) in self._failed_endpoints
        ]

        # Combine in order of preference
        ordered_endpoints = working_endpoints + unknown_endpoints + failed_endpoints

        for endpoint_pattern in ordered_endpoints:
            endpoint = endpoint_pattern.format(**format_args)

            # Skip if we know this endpoint pattern fails
            if endpoint in self._failed_endpoints and endpoint not in working_endpoints:
                logger.debug(f"Skipping known failed endpoint: {endpoint}")
                continue

            try:
                url = urljoin(self.base_url, endpoint)

                # Use suppress_expected_404 for endpoint exploration
                with debug_http_request(
                    "GET", url, suppress_expected_404=True
                ) as debug_ctx:
                    response = await self._client.request("GET", url)
                    response.raise_for_status()

                    debug_ctx.log_response(response)
                    data = response.json()

                    # Mark this endpoint as working
                    self._working_endpoints.add(endpoint)

                    # Different endpoints may return data in different formats
                    if "data" in data:
                        successful_data = data.get("data", {})
                        if isinstance(successful_data, dict):
                            return successful_data.get("image") or successful_data
                        return successful_data
                    elif (
                        "_id" in data
                        or "repository" in data
                        or "rpms" in data
                        or "manifest" in data
                    ):
                        return data

            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404:
                    # Mark this endpoint as failed
                    self._failed_endpoints.add(endpoint)
                    logger.debug(f"Endpoint 404 (added to failed list): {endpoint}")
                    continue
                # For other errors, log but continue trying
                logger.debug(f"Error with endpoint {endpoint}: {e}")
                continue
            except Exception as e:
                logger.debug(f"Unexpected error with endpoint {endpoint}: {e}")
                continue

        logger.debug(f"No working endpoints found for patterns: {endpoint_patterns}")
        return successful_data

    async def search_containers(
        self,
        query: str,
        page: int = 1,
        page_size: int = 100,
        filter_params: Optional[Dict[str, str]] = None,
    ) -> CatalogSearchResult:
        """Search for containers in the catalog.

        Note: The Red Hat Container Catalog API doesn't support query parameters.
        This method now fetches all containers and filters locally.

        Args:
            query: Search query string (used for local filtering)
            page: Page number (1-based)
            page_size: Number of results per page
            filter_params: Additional filter parameters (used for local filtering)

        Returns:
            Search results with container metadata

        Raises:
            httpx.HTTPError: On API request failures
        """
        async with self._semaphore:
            url = urljoin(self.base_url, "repositories")

            # The API only supports page and page_size parameters
            params = {
                "page": page,
                "page_size": min(page_size, 100),  # API limit
            }

            logger.info(
                f"Fetching containers: page={page}, will filter locally for query='{query}'"
            )

            response = await self._make_request("GET", url, params=params)
            data = response.json()

            # Parse response data and filter locally
            images = []
            total_items = len(data.get("data", []))
            logger.debug(f"API returned {total_items} items on page {page}")

            for item in data.get("data", []):
                try:
                    # Log some details about each item for debugging
                    repo = item.get("repository", "")
                    namespace = item.get("namespace", "")
                    if (
                        page == 1 and len(images) < 3
                    ):  # Log first few items on first page
                        logger.debug(f"Item: namespace={namespace}, repository={repo}")

                    # Check if this item matches our search criteria
                    if self._matches_search_criteria(item, query, filter_params):
                        image = self._parse_container_data(item)
                        images.append(image)
                except Exception as e:
                    logger.warning(f"Failed to parse container data: {e}")
                    continue

            return CatalogSearchResult(
                total=data.get("total", 0),
                page=page,
                page_size=page_size,
                images=images,
            )

    async def get_container_details(
        self, container_id: str
    ) -> Optional[ContainerImage]:
        """Get detailed information for a specific container.

        Args:
            container_id: Container identifier

        Returns:
            Container details or None if not found
        """
        async with self._semaphore:
            url = urljoin(self.base_url, f"repositories/{container_id}")

            try:
                response = await self._make_request("GET", url)
                data = response.json()
                return self._parse_container_data(data)
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404:
                    logger.warning(f"Container not found: {container_id}")
                    return None
                raise

    async def discover_rhoai_containers(
        self,
        release_version: str,
        filter_names: Optional[List[str]] = None,
        manual_containers: Optional[List[Dict[str, str]]] = None,
        hybrid_discovery: bool = True,
    ) -> List[ContainerImage]:
        """Discover all RHOAI containers for a specific release.

        Args:
            release_version: RHOAI release version (e.g., "2.8.0")
            filter_names: Optional list of container names to filter by
            manual_containers: Optional list of manually specified containers
            hybrid_discovery: Whether to combine manual + API discovery (default: True)

        Returns:
            List of container images for the release
        """
        logger.info(f"Discovering RHOAI containers for release {release_version}")

        all_containers = []
        seen_digests = set()
        manual_count = 0
        api_count = 0

        # Phase 1: Process manual containers if provided
        if manual_containers:
            logger.info(
                f"Processing {len(manual_containers)} manually configured containers for release {release_version}"
            )
            for container_spec in manual_containers:
                try:
                    # Create ContainerImage from manual specification
                    namespace = container_spec.get("namespace", "")
                    repository = container_spec.get("repository", "")
                    registry = container_spec.get("registry", "registry.redhat.io")

                    container = ContainerImage(
                        name=repository,
                        registry_url=f"{registry}/{namespace}/{repository}",
                        digest=f"manual-{namespace}-{repository}",
                        tag=release_version,
                        created_at=datetime.now(),
                        architecture="x86_64",
                    )

                    # Apply name filter if specified
                    if filter_names and not any(
                        name.lower() in container.name.lower() for name in filter_names
                    ):
                        logger.debug(
                            f"Skipping container {repository} - doesn't match filter"
                        )
                        continue

                    all_containers.append(container)
                    seen_digests.add(container.digest)
                    manual_count += 1
                    logger.debug(f"Added manual container: {container.registry_url}")

                except Exception as e:
                    logger.warning(f"Failed to process manual container spec: {e}")

            logger.info(
                f"Successfully loaded {manual_count} containers from manual configuration"
            )

            # If hybrid discovery is disabled, return only manual containers
            if not hybrid_discovery:
                if not all_containers:
                    raise ValueError(
                        f"No containers found for release {release_version} in manual configuration"
                    )
                return all_containers

        # Phase 2: API Discovery - Enhanced search patterns for comprehensive coverage
        logger.info(
            f"Starting API discovery for release {release_version} (hybrid_discovery={hybrid_discovery})"
        )

        # Comprehensive search patterns covering all known RHOAI/OpenShift AI variations
        search_patterns = [
            # Core product names
            "rhoai",
            "openshift-ai",
            "openshift ai",
            "rhods",  # Legacy Red Hat OpenShift Data Science
            "red hat openshift ai",
            "openshift data science",
            # Component-specific patterns
            "odh",  # Open Data Hub components
            "kubeflow",
            "modelmesh",
            "kserve",
            "trustyai",
            "codeflare",
            "ray",
            "notebook",
            "workbench",
            "pytorch",
            "tensorflow",
            "triton",
            "openvino",
            "habana",
            "intel",
            # Operator patterns
            "rhods-operator",
            "data-science",
            "ml-pipelines",
            "pipelines",
            # Jupyter/notebook patterns
            "jupyter",
            "notebook-controller",
            "workbench-images",
            # Additional infrastructure
            "dashboard",
            "oauth-proxy",
            "rest-proxy",
        ]

        # Namespace patterns to search within
        namespace_patterns = ["rhoai", "openshift-ai", "rhods", "odh", "redhat-ods"]

        for pattern in search_patterns:
            try:
                page = 1
                consecutive_empty_pages = 0
                pattern_containers = 0

                while (
                    consecutive_empty_pages < 3
                ):  # Stop after 3 consecutive empty result pages
                    result = await self.search_containers(
                        query=pattern,
                        page=page,
                        page_size=100,
                        filter_params={"vendor": "redhat"},
                    )

                    # Count how many containers we found on this page
                    page_containers = 0

                    logger.debug(
                        f"Pattern '{pattern}' Page {page}: Found {len(result.images)} containers"
                    )

                    # Filter containers
                    for container in result.images:
                        # Avoid duplicates (check both digest and registry_url)
                        container_key = f"{container.digest}-{container.registry_url}"
                        if (
                            container.digest in seen_digests
                            or container_key in seen_digests
                        ):
                            continue

                        # Apply name filter if specified
                        if filter_names and not any(
                            name.lower() in container.name.lower()
                            for name in filter_names
                        ):
                            continue

                        # Enhanced matching: check if container is RHOAI-related
                        if self._is_rhoai_container(container, namespace_patterns):
                            # Verify this is actually for the requested release
                            if self._is_release_match(container, release_version):
                                logger.info(f"Found API container: {container.name}")
                                all_containers.append(container)
                                seen_digests.add(container.digest)
                                seen_digests.add(container_key)
                                page_containers += 1
                                pattern_containers += 1
                                api_count += 1

                    # Track empty pages
                    if page_containers == 0:
                        consecutive_empty_pages += 1
                    else:
                        consecutive_empty_pages = 0

                    # Check if we've reached the end of results
                    if result.total > 0 and page * result.page_size >= result.total:
                        break

                    page += 1

                    # Safety limit to prevent infinite loops
                    # TODO: Make this configurable via Config
                    if page > 100:  # This could be made configurable in the future
                        logger.warning(f"Reached page limit for pattern '{pattern}'")
                        break

                logger.debug(
                    f"Pattern '{pattern}' found {pattern_containers} new containers"
                )

            except Exception as e:
                logger.warning(f"Failed to search with pattern '{pattern}': {e}")
                continue

        # Summary logging
        total_containers = len(all_containers)
        logger.info(f"Discovery complete for release {release_version}:")
        logger.info(f"  Manual containers: {manual_count}")
        logger.info(f"  API discovered: {api_count}")
        logger.info(f"  Total containers: {total_containers}")

        if total_containers == 0:
            if manual_containers:
                raise ValueError(
                    f"No containers found for release {release_version} (manual config had {len(manual_containers)} entries but none matched filters)"
                )
            else:
                raise ValueError(
                    f"No containers found for release {release_version} via API discovery"
                )

        return all_containers

    async def get_container_vulnerabilities(self, container_id: str) -> Dict[str, Any]:
        """Get vulnerability information for a container.

        Args:
            container_id: Container identifier

        Returns:
            Vulnerability data from the catalog
        """
        async with self._semaphore:
            url = urljoin(self.base_url, f"repositories/{container_id}/vulnerabilities")

            try:
                response = await self._make_request("GET", url)
                return response.json()
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404:
                    logger.warning(f"No vulnerability data found for: {container_id}")
                    return {}
                raise

    async def get_image_by_id(self, image_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed image information by image ID using GraphQL endpoint.

        Args:
            image_id: Image identifier

        Returns:
            Image metadata or None if not found
        """
        # For manual containers, skip API call
        if image_id.startswith("manual-"):
            logger.debug(f"Skipping API call for manual container: {image_id}")
            return None

        async with self._semaphore:
            # Define endpoint patterns to try
            endpoint_patterns = [
                "images/by_id?image_id={image_id}",
                "images/{image_id}",
                "repositories/registry/access.redhat.com/rhoai/{image_id}",
            ]

            # Use smart endpoint handling
            result = await self._try_endpoints_smartly(
                endpoint_patterns, image_id=image_id
            )

            if result is None:
                logger.warning(f"Image not found with any endpoint: {image_id}")
            else:
                logger.debug(f"Successfully retrieved image data for: {image_id}")

            return result

    async def get_rpm_manifest(self, image_id: str) -> Optional[Dict[str, Any]]:
        """Get RPM manifest for a container image.

        Args:
            image_id: Image identifier

        Returns:
            RPM manifest data or None if not found
        """
        # For manual containers, skip API call
        if image_id.startswith("manual-"):
            logger.debug(
                f"Skipping RPM manifest API call for manual container: {image_id}"
            )
            return None

        async with self._semaphore:
            # Define endpoint patterns to try
            endpoint_patterns = [
                "images/rpm_manifest?image_id={image_id}",
                "images/{image_id}/rpm-manifest",
                "repositories/{image_id}/manifest",
            ]

            # Use smart endpoint handling
            result = await self._try_endpoints_smartly(
                endpoint_patterns, image_id=image_id
            )

            # Additional processing for RPM manifest specific formats
            if result and "data" in result and "rpm_manifest" in result["data"]:
                result = result["data"]["rpm_manifest"]
            elif result and "manifest" in result:
                result = result["manifest"]

            if result is None:
                logger.debug(f"No RPM manifest found with any endpoint for: {image_id}")
            else:
                logger.debug(f"Successfully retrieved RPM manifest for: {image_id}")

            return result

    async def get_image_vulnerabilities(self, image_id: str) -> List[Dict[str, Any]]:
        """Get vulnerabilities for a specific image using GraphQL endpoint.

        Args:
            image_id: Image identifier

        Returns:
            List of vulnerabilities
        """
        async with self._semaphore:
            # Use the GraphQL endpoint for vulnerabilities
            url = urljoin(self.base_url, "images/vulnerabilities")

            try:
                response = await self._make_request(
                    "GET", url, params={"image_id": image_id}
                )
                data = response.json()
                return data.get("data", {}).get("vulnerabilities", [])
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404:
                    logger.warning(f"No vulnerabilities found for image: {image_id}")
                    return []
                raise

    async def _make_request(
        self, method: str, url: str, params: Optional[Dict] = None, **kwargs
    ) -> httpx.Response:
        """Make HTTP request with retry logic.

        Args:
            method: HTTP method
            url: Request URL
            params: Query parameters
            **kwargs: Additional request arguments

        Returns:
            HTTP response

        Raises:
            httpx.HTTPError: On request failures after retries
        """
        last_exception = None

        # Log request details in debug mode
        request_headers = dict(self._client.headers)
        request_headers.update(kwargs.get("headers", {}))
        request_content = kwargs.get("content") or kwargs.get("data")
        if request_content and hasattr(request_content, "decode"):
            request_content = request_content.decode("utf-8", errors="ignore")

        for attempt in range(self.max_retries + 1):
            # Don't suppress 404s for regular API calls, only for endpoint exploration
            with debug_http_request(
                method, url, params, request_headers, request_content
            ) as debug_ctx:
                try:
                    response = await self._client.request(
                        method, url, params=params, **kwargs
                    )
                    response.raise_for_status()

                    # Log successful response in debug mode
                    debug_ctx.log_response(response)
                    return response

                except httpx.HTTPError as e:
                    last_exception = e

                    if attempt < self.max_retries:
                        # Calculate backoff delay
                        delay = 2**attempt + (attempt * 0.1)
                        logger.debug(
                            f"Request failed (attempt {attempt + 1}/{self.max_retries + 1}): {e}"
                        )
                        logger.debug(f"Retrying in {delay:.1f} seconds...")
                        await asyncio.sleep(delay)
                    else:
                        logger.debug(
                            f"Request failed after {self.max_retries + 1} attempts: {e}"
                        )

        # Re-raise the last exception
        raise last_exception

    def _parse_container_data(self, data: Dict[str, Any]) -> ContainerImage:
        """Parse container data from API response.

        Args:
            data: Raw container data from API

        Returns:
            Parsed container image object
        """
        # Extract basic information
        # The API returns repository path, not just name
        repository = data.get("repository", "")
        name = repository.split("/")[-1] if repository else data.get("name", "")

        # Build registry URL
        registry = data.get("registry", "registry.access.redhat.com")
        registry_url = (
            f"{registry}/{repository}" if repository else data.get("registry_url", "")
        )

        # Extract digest - may be in different locations
        digest = (
            data.get("digest")
            or data.get("image_digest")
            or data.get("content_sets", [{}])[0].get("digest", "")
            or f"unknown-{repository}"  # Fallback digest
        )

        # Extract tag - look in content_stream_tags
        tags = data.get("content_stream_tags", [])
        tag = tags[0] if tags else data.get("tag", "latest")

        # Parse creation date
        created_str = data.get("creation_date") or data.get("created_at")
        created_at = datetime.now()
        if created_str:
            try:
                created_at = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                logger.warning(f"Could not parse creation date: {created_str}")

        # Extract additional metadata
        architecture = data.get("architecture", "x86_64")
        size_bytes = data.get("total_size_bytes") or data.get("size_bytes")
        layers = data.get("layers", [])
        labels = data.get("labels", {})

        return ContainerImage(
            name=name,
            registry_url=registry_url,
            digest=digest,
            tag=tag,
            created_at=created_at,
            architecture=architecture,
            size_bytes=size_bytes,
            layers=layers,
            labels=labels,
        )

    def _matches_search_criteria(
        self,
        item: Dict[str, Any],
        query: str,
        filter_params: Optional[Dict[str, str]] = None,
    ) -> bool:
        """Check if a repository item matches search criteria.

        Args:
            item: Raw repository data from API
            query: Search query string
            filter_params: Additional filter parameters

        Returns:
            True if item matches the search criteria
        """
        # First check if query matches any text fields
        query_matched = False
        if query:
            # Convert query to lowercase for case-insensitive matching
            query_lower = query.lower()

            # Check repository name
            repo_name = item.get("repository", "").lower()
            if query_lower in repo_name:
                query_matched = True

            # Check namespace
            namespace = item.get("namespace", "").lower()
            if query_lower in namespace:
                query_matched = True

            # Check description
            description = item.get("description", "").lower()
            if query_lower in description:
                query_matched = True

            # Check display_data fields
            display_data = item.get("display_data", {})
            if query_lower in display_data.get("name", "").lower():
                query_matched = True
            if query_lower in display_data.get("short_description", "").lower():
                query_matched = True

            # If query didn't match any field, return False
            if not query_matched:
                return False

        # Apply additional filters if provided
        if filter_params:
            # Check vendor
            if "vendor" in filter_params:
                vendor_label = item.get("vendor_label", "")
                if filter_params["vendor"] != vendor_label:
                    return False

            # Check architecture
            if "architecture" in filter_params:
                architectures = item.get("architectures", [])
                arch_found = filter_params["architecture"] in architectures

                # Also check in content_stream_grades for architecture info
                if not arch_found:
                    for grade in item.get("content_stream_grades", []):
                        for image_id in grade.get("image_ids", []):
                            if image_id.get("arch") == filter_params["architecture"]:
                                arch_found = True
                                break
                        if arch_found:
                            break

                if not arch_found:
                    return False

        # If we've passed all checks (query matched if provided, and all filters pass), return True
        return True

    def _is_rhoai_container(
        self, container: ContainerImage, namespace_patterns: List[str]
    ) -> bool:
        """Check if a container belongs to RHOAI/OpenShift AI.

        Args:
            container: Container image to check
            namespace_patterns: List of namespace patterns to match against

        Returns:
            True if container is RHOAI-related
        """
        # Check registry URL for RHOAI namespaces
        registry_url_lower = container.registry_url.lower()
        for namespace in namespace_patterns:
            if f"/{namespace}/" in registry_url_lower:
                logger.debug(
                    f"Container {container.name} matches namespace pattern: {namespace}"
                )
                return True

        # Check container name for RHOAI indicators
        name_lower = container.name.lower()
        rhoai_indicators = [
            "rhoai",
            "rhods",
            "odh",
            "openshift-ai",
            "data-science",
            "kubeflow",
            "modelmesh",
            "kserve",
            "trustyai",
            "codeflare",
            "notebook",
            "workbench",
            "jupyter",
        ]

        for indicator in rhoai_indicators:
            if indicator in name_lower:
                logger.debug(
                    f"Container {container.name} matches name indicator: {indicator}"
                )
                return True

        # Check labels for RHOAI/OpenShift AI indicators
        for label_key, label_value in container.labels.items():
            label_key_lower = str(label_key).lower()
            label_value_lower = str(label_value).lower()

            if any(
                indicator in label_key_lower or indicator in label_value_lower
                for indicator in rhoai_indicators
            ):
                logger.debug(
                    f"Container {container.name} matches label: {label_key}={label_value}"
                )
                return True

        return False

    def _is_release_match(
        self, container: ContainerImage, release_version: str
    ) -> bool:
        """Check if container matches the specified release version.

        Args:
            container: Container image to check
            release_version: Target release version

        Returns:
            True if container matches the release
        """
        # For manually configured containers, always assume they match the requested version
        if container.digest.startswith("manual-"):
            logger.debug(
                f"Manual container {container.name} assumed to match version {release_version}"
            )
            return True

        # Check tag - look for exact version match
        if container.tag:
            # Check for exact match or version as part of tag
            if (
                release_version == container.tag
                or f"-{release_version}" in container.tag
            ):
                logger.debug(
                    f"Container {container.name} matches by tag: {container.tag}"
                )
                return True

        # Check registry URL for version
        if release_version in container.registry_url:
            logger.debug(f"Container {container.name} matches by registry URL")
            return True

        # Check labels for version information
        version_keys = ["version", "release", "com.redhat.component.version"]
        for key in version_keys:
            if key in container.labels:
                label_value = str(container.labels[key])
                if release_version == label_value or release_version in label_value:
                    logger.debug(
                        f"Container {container.name} matches by label {key}: {label_value}"
                    )
                    return True

        # If no version information found, log and reject
        logger.debug(
            f"Container {container.name} does not match version {release_version}"
        )
        return False


async def create_catalog_client(config) -> ContainerCatalogClient:
    """Create and configure a container catalog client.

    Args:
        config: Application configuration

    Returns:
        Configured catalog client
    """
    return ContainerCatalogClient(
        timeout=config.api.timeout,
        max_retries=config.api.max_retries,
        max_concurrent=config.api.max_concurrent_requests,
    )
