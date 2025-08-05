"""Red Hat Container Catalog API client."""

import asyncio
from datetime import datetime
from typing import Any, Optional
from urllib.parse import urljoin

import httpx
from pydantic import BaseModel, Field

from ..utils.http_debug import debug_http_request
from ..utils.logging import get_logger
from .product_listings import ProductListingsClient

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
    layers: list[str] = Field(default_factory=list)
    labels: dict[str, str] = Field(default_factory=dict)


class CatalogSearchResult(BaseModel):
    """Search result from container catalog."""

    total: int
    page: int
    page_size: int
    images: list[ContainerImage]


class ContainerCatalogClient:
    """Client for Red Hat Container Catalog API."""

    def __init__(
        self,
        base_url: str = "https://catalog.redhat.com/api/containers/v1/",
        timeout: int = 30,
        max_retries: int = 3,
        max_concurrent: int = 10,
        product_listings_client: Optional[ProductListingsClient] = None,
    ):
        """Initialize the catalog client.

        Args:
            base_url: Base URL for the Container Catalog API
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            max_concurrent: Maximum concurrent requests
            product_listings_client: Optional product listings client for API-based discovery
        """
        self.base_url = base_url.rstrip("/") + "/"
        self.timeout = timeout
        self.max_retries = max_retries
        self.max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._product_listings_client = product_listings_client

        # Track failed endpoints to avoid repeated 404s
        self._failed_endpoints = set()
        self._working_endpoints = set()

        # Cache for API responses to avoid redundant calls
        self._response_cache = {}

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
        self, endpoint_patterns: list[str], **format_args
    ) -> Optional[dict[str, Any]]:
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
                    # Only log at debug level for expected 404s during endpoint exploration
                    logger.debug(f"Endpoint exploration 404 (expected): {endpoint}")
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
        filter_params: Optional[dict[str, str]] = None,
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

    async def _targeted_api_discovery(
        self,
        container_repos: list,
        release_version: str,
        filter_names: Optional[list[str]] = None,
    ) -> list[ContainerImage]:
        """Perform targeted API discovery for specific container repositories.

        Args:
            container_repos: List of container repositories from Product Listings
            release_version: Target release version
            filter_names: Optional list of container names to filter by

        Returns:
            List of verified container images from the API
        """
        logger.info(
            f"Starting targeted API discovery for {len(container_repos)} containers"
        )

        verified_containers = []
        verification_tasks = []

        # Create targeted verification tasks
        for repo in container_repos:
            # Apply name filter if specified
            if filter_names and not any(
                name.lower() in repo.repository.lower() for name in filter_names
            ):
                continue

            # Create verification task for this specific container
            verification_tasks.append(
                self._verify_container_exists(repo, release_version)
            )

        if not verification_tasks:
            logger.info("No containers to verify after filtering")
            return verified_containers

        logger.info(
            f"Verifying {len(verification_tasks)} containers via targeted API calls"
        )

        # Execute verification tasks in parallel with semaphore control
        results = await asyncio.gather(*verification_tasks, return_exceptions=True)

        # Process results
        for result in results:
            if isinstance(result, Exception):
                logger.debug(f"Verification task failed: {result}")
                continue
            if result:  # Successfully verified container
                verified_containers.append(result)

        logger.info(
            f"Successfully verified {len(verified_containers)} containers via API"
        )
        return verified_containers

    async def _verify_container_exists(
        self, repo, release_version: str
    ) -> Optional[ContainerImage]:
        """Verify a specific container exists via targeted API calls.

        Args:
            repo: Container repository info from Product Listings
            release_version: Target release version

        Returns:
            ContainerImage if found, None otherwise
        """
        async with self._semaphore:
            # Try multiple targeted endpoints for this specific container
            container_id = f"{repo.namespace}/{repo.repository}"
            cache_key = f"verify_{container_id}_{release_version}"

            # Check cache first
            if cache_key in self._response_cache:
                cached_result = self._response_cache[cache_key]
                if cached_result:
                    logger.debug(f"Using cached result for {container_id}")
                    return cached_result
                return None

            # Try targeted endpoints
            endpoint_patterns = [
                f"repositories/{repo.namespace}/{repo.repository}",
                f"repositories/registry/registry.redhat.io/{repo.namespace}/{repo.repository}",
                f"repositories/id/{repo.namespace}-{repo.repository}",
            ]

            for endpoint in endpoint_patterns:
                try:
                    url = urljoin(self.base_url, endpoint)

                    # Check if we've already tried this endpoint and it failed
                    if endpoint in self._failed_endpoints:
                        continue

                    response = await self._client.request("GET", url)

                    if response.status_code == 200:
                        data = response.json()

                        # Parse the container data
                        container = self._parse_container_data(data)

                        # Verify it matches our release version
                        if self._is_release_match(container, release_version):
                            # Cache the successful result
                            self._response_cache[cache_key] = container
                            self._working_endpoints.add(endpoint)

                            logger.debug(f"Verified container via API: {container_id}")
                            return container
                        else:
                            logger.debug(
                                f"Container {container_id} found but version mismatch"
                            )

                    elif response.status_code == 404:
                        # Mark this specific endpoint as failed
                        self._failed_endpoints.add(endpoint)

                except Exception as e:
                    logger.debug(f"Error verifying {container_id} via {endpoint}: {e}")
                    continue

            # Cache negative result to avoid repeated attempts
            self._response_cache[cache_key] = None
            logger.debug(f"Could not verify container via API: {container_id}")
            return None

    async def discover_rhoai_containers(
        self,
        release_version: str,
        filter_names: Optional[list[str]] = None,
        manual_containers: Optional[list[dict[str, str]]] = None,
        hybrid_discovery: bool = True,
        use_product_listings: bool = True,
        discovery_strategy: str = "product_listings_primary",
    ) -> list[ContainerImage]:
        """Discover all RHOAI containers for a specific release.

        Args:
            release_version: RHOAI release version (e.g., "2.8.0")
            filter_names: Optional list of container names to filter by
            manual_containers: Optional list of manually specified containers
            hybrid_discovery: Whether to combine manual + API discovery (default: True)
            use_product_listings: Whether to use Product Listings API for discovery (default: True)
            discovery_strategy: Discovery strategy to use:
                - "product_listings_primary": Use Product Listings as primary source (recommended)
                - "targeted_api": Use targeted API verification for Product Listings containers
                - "broad_search": Use original broad search approach (legacy)

        Returns:
            List of container images for the release
        """
        logger.info(
            f"Discovering RHOAI containers for release {release_version} using strategy: {discovery_strategy}"
        )

        all_containers = []
        seen_digests = set()
        manual_count = 0
        api_count = 0
        product_listings_count = 0
        targeted_api_count = 0

        # Phase 0: Product Listings API Discovery (if enabled and client available)
        if use_product_listings and self._product_listings_client:
            try:
                logger.info("Attempting container discovery via Product Listings API")
                product_listing = (
                    await self._product_listings_client.get_openshift_ai_product()
                )

                if product_listing:
                    container_repos = (
                        await self._product_listings_client.map_version_to_containers(
                            product_listing, release_version
                        )
                    )

                    if discovery_strategy == "product_listings_primary":
                        # Convert ProductListing containers to ContainerImage objects directly
                        for repo in container_repos:
                            # Apply name filter if specified
                            if filter_names and not any(
                                name.lower() in repo.repository.lower()
                                for name in filter_names
                            ):
                                logger.debug(
                                    f"Skipping container {repo.repository} - doesn't match filter"
                                )
                                continue

                            # Use namespace/repository format for proper API queries
                            image_id = f"{repo.namespace}/{repo.repository}"
                            container = ContainerImage(
                                name=repo.repository,
                                registry_url=f"{repo.registry}/{repo.namespace}/{repo.repository}",
                                digest=image_id,  # Use proper namespace/repository format
                                tag=release_version,
                                created_at=datetime.now(),
                                architecture="x86_64",
                                labels={
                                    "source": "product_listings",
                                    "bundle": repo.source_bundle or "",
                                    "ocp_versions": ",".join(repo.ocp_versions),
                                    "categories": ",".join(repo.categories),
                                },
                            )

                            all_containers.append(container)
                            seen_digests.add(container.digest)
                            product_listings_count += 1
                            logger.debug(
                                f"Added Product Listings container: {container.registry_url}"
                            )

                        logger.info(
                            f"Successfully discovered {product_listings_count} containers via Product Listings API"
                        )

                    elif discovery_strategy == "targeted_api":
                        # Use targeted API discovery to verify Product Listings containers
                        logger.info(
                            "Using targeted API discovery to verify Product Listings containers"
                        )
                        verified_containers = await self._targeted_api_discovery(
                            container_repos, release_version, filter_names
                        )

                        # Use verified containers or fall back to Product Listings data
                        if verified_containers:
                            all_containers.extend(verified_containers)
                            for container in verified_containers:
                                seen_digests.add(container.digest)
                            targeted_api_count = len(verified_containers)
                            logger.info(
                                f"Successfully verified {targeted_api_count} containers via targeted API"
                            )
                        else:
                            # Fall back to Product Listings data if API verification fails
                            logger.warning(
                                "Targeted API verification failed, falling back to Product Listings data"
                            )
                            for repo in container_repos:
                                if filter_names and not any(
                                    name.lower() in repo.repository.lower()
                                    for name in filter_names
                                ):
                                    continue

                                # Use namespace/repository format for proper API queries
                                image_id = f"{repo.namespace}/{repo.repository}"
                                container = ContainerImage(
                                    name=repo.repository,
                                    registry_url=f"{repo.registry}/{repo.namespace}/{repo.repository}",
                                    digest=image_id,  # Use proper namespace/repository format
                                    tag=release_version,
                                    created_at=datetime.now(),
                                    architecture="x86_64",
                                    labels={
                                        "source": "product_listings_fallback",
                                        "bundle": repo.source_bundle or "",
                                        "ocp_versions": ",".join(repo.ocp_versions),
                                        "categories": ",".join(repo.categories),
                                    },
                                )

                                all_containers.append(container)
                                seen_digests.add(container.digest)
                                product_listings_count += 1

                    # If we found containers and hybrid discovery is disabled, return them
                    if (
                        product_listings_count > 0 or targeted_api_count > 0
                    ) and not hybrid_discovery:
                        total_found = product_listings_count + targeted_api_count
                        logger.info(
                            f"Discovery complete (hybrid disabled): {total_found} containers"
                        )
                        return all_containers
                else:
                    logger.warning(
                        "No OpenShift AI product found in Product Listings API"
                    )

            except Exception as e:
                logger.warning(f"Product Listings API discovery failed: {e}")
                logger.info("Falling back to manual/search discovery methods")
        elif use_product_listings and not self._product_listings_client:
            logger.warning("Product Listings API requested but no client provided")
        else:
            logger.debug("Product Listings API discovery disabled")

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

                    # Use namespace/repository format for consistency
                    image_id = f"{namespace}/{repository}" if namespace else repository
                    container = ContainerImage(
                        name=repository,
                        registry_url=f"{registry}/{namespace}/{repository}",
                        digest=f"manual-{image_id}",  # Keep manual prefix but use proper format
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
        # Only perform broad search if explicitly requested or as fallback
        if discovery_strategy == "broad_search" or (
            discovery_strategy in ["product_listings_primary", "targeted_api"]
            and hybrid_discovery
            and product_listings_count == 0
            and targeted_api_count == 0
        ):
            logger.info(
                f"Starting broad API discovery for release {release_version} (strategy={discovery_strategy}, hybrid_discovery={hybrid_discovery})"
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

            # Namespace patterns to search within - including alternative namespaces
            namespace_patterns = [
                "rhoai",
                "openshift-ai",
                "rhods",
                "odh",
                "redhat-ods",
                "ubi8",
                "rhel8",
                "openshift4",
                "registry.redhat.io",
                "redhat",
            ]

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
                            container_key = (
                                f"{container.digest}-{container.registry_url}"
                            )
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
                                    logger.info(
                                        f"Found API container: {container.name}"
                                    )
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
                        # Use configurable page limit
                        max_pages = getattr(self, "_max_api_pages", 100)
                        if page > max_pages:
                            logger.warning(
                                f"Reached page limit ({max_pages}) for pattern '{pattern}'"
                            )
                            break

                    logger.debug(
                        f"Pattern '{pattern}' found {pattern_containers} new containers"
                    )

                except Exception as e:
                    logger.warning(f"Failed to search with pattern '{pattern}': {e}")
                    continue

        # Summary logging
        total_containers = len(all_containers)
        logger.info(
            f"Discovery complete for release {release_version} (strategy: {discovery_strategy}):"
        )
        logger.info(f"  Product Listings API: {product_listings_count}")
        logger.info(f"  Targeted API verified: {targeted_api_count}")
        logger.info(f"  Manual containers: {manual_count}")
        logger.info(f"  Broad search API discovered: {api_count}")
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

    async def get_container_vulnerabilities(self, container_id: str) -> dict[str, Any]:
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

    async def get_image_by_id(self, image_id: str) -> Optional[dict[str, Any]]:
        """Get detailed image information by image ID.

        Args:
            image_id: Image identifier (can be namespace/repository format)

        Returns:
            Image metadata or None if not found
        """
        # For manual containers, skip API call
        if image_id.startswith("manual-") or image_id.startswith("product-listings-"):
            logger.debug(
                f"Skipping API call for manual/product-listings container: {image_id}"
            )
            return None

        async with self._semaphore:
            # Parse image_id - it could be in format namespace/repository or just repository
            if "/" in image_id:
                namespace, repository = image_id.split("/", 1)
            else:
                # Try common RHOAI namespace
                namespace = "rhoai"
                repository = image_id

            # Define endpoint patterns using the repositories API structure
            # Include broader search patterns that might find containers in alternative namespaces
            endpoint_patterns = [
                "repositories/{namespace}/{repository}",
                "repositories/registry/registry.redhat.io/{namespace}/{repository}",
                "repositories/registry/registry.access.redhat.com/{namespace}/{repository}",
                "repositories?filter=namespace=={namespace};repository=={repository}",
                "repositories?filter=repository=={repository}",  # Search without namespace restriction
                "repositories?filter=repository~~{repository}",  # Fuzzy repository search
            ]

            # Use smart endpoint handling
            result = await self._try_endpoints_smartly(
                endpoint_patterns, namespace=namespace, repository=repository
            )

            if result is None:
                logger.warning(f"Image not found with any endpoint: {image_id}")
            else:
                logger.debug(f"Successfully retrieved image data for: {image_id}")

            return result

    async def get_rpm_manifest(self, image_id: str) -> Optional[dict[str, Any]]:
        """Get RPM manifest for a container image.

        Args:
            image_id: Image identifier (can be namespace/repository format)

        Returns:
            RPM manifest data or None if not found
        """
        # For manual containers, skip API call
        if image_id.startswith("manual-") or image_id.startswith("product-listings-"):
            logger.debug(
                f"Skipping RPM manifest API call for manual/product-listings container: {image_id}"
            )
            return None

        async with self._semaphore:
            # Parse image_id - it could be in format namespace/repository or just repository
            if "/" in image_id:
                namespace, repository = image_id.split("/", 1)
            else:
                # Try common RHOAI namespace
                namespace = "rhoai"
                repository = image_id

            # Define endpoint patterns for RPM manifest
            # Include broader search patterns for finding container manifests
            endpoint_patterns = [
                "repositories/{namespace}/{repository}/images",
                "repositories/{namespace}/{repository}/manifest",
                "repositories/registry/registry.redhat.io/{namespace}/{repository}/images",
                "repositories?filter=repository=={repository}/images",  # Search without namespace restriction
                "repositories?filter=repository~~{repository}/manifest",  # Fuzzy search for manifests
            ]

            # Use smart endpoint handling
            result = await self._try_endpoints_smartly(
                endpoint_patterns, namespace=namespace, repository=repository
            )

            # Try to extract RPM manifest from repository data
            if result:
                # If we got repository data with images, try to find RPM manifest
                if isinstance(result, dict):
                    if "images" in result:
                        # Look for RPM manifest in the first image
                        images = result["images"]
                        if images and len(images) > 0:
                            first_image = images[0]
                            if "manifest" in first_image:
                                result = first_image["manifest"]
                            elif "rpm_manifest" in first_image:
                                result = first_image["rpm_manifest"]
                    elif "manifest" in result:
                        result = result["manifest"]
                    elif "rpm_manifest" in result:
                        result = result["rpm_manifest"]

            if result is None:
                logger.debug(f"No RPM manifest found with any endpoint for: {image_id}")
            else:
                logger.debug(f"Successfully retrieved RPM manifest for: {image_id}")

            return result

    async def get_image_vulnerabilities(self, image_id: str) -> list[dict[str, Any]]:
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
        self, method: str, url: str, params: Optional[dict] = None, **kwargs
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

                    # Handle specific HTTP status codes
                    if hasattr(e, "response") and e.response:
                        if e.response.status_code == 401:
                            logger.error(
                                "Authentication required. The Red Hat Container Catalog API may require an API key."
                            )
                            logger.info(
                                "Please contact pyxis-dev@redhat.com for API access information."
                            )
                            break  # Don't retry auth errors
                        elif e.response.status_code == 403:
                            logger.error(
                                "Access forbidden. Your API credentials may not have sufficient permissions."
                            )
                            break  # Don't retry permission errors
                        elif e.response.status_code == 429:
                            # Rate limiting - use longer delay
                            delay = min(
                                60, 5 * (2**attempt)
                            )  # Exponential backoff up to 60s
                            logger.warning(
                                f"Rate limited. Waiting {delay}s before retry..."
                            )
                            await asyncio.sleep(delay)
                            continue

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

    def _parse_container_data(self, data: dict[str, Any]) -> ContainerImage:
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
        item: dict[str, Any],
        query: str,
        filter_params: Optional[dict[str, str]] = None,
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
        self, container: ContainerImage, namespace_patterns: list[str]
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


async def create_catalog_client(
    config, product_listings_client: Optional[ProductListingsClient] = None
) -> ContainerCatalogClient:
    """Create and configure a container catalog client.

    Args:
        config: Application configuration
        product_listings_client: Optional product listings client for enhanced discovery

    Returns:
        Configured catalog client
    """
    client = ContainerCatalogClient(
        timeout=config.api.timeout,
        max_retries=config.api.max_retries,
        max_concurrent=config.api.max_concurrent_requests,
        product_listings_client=product_listings_client,
    )

    # Set discovery configuration
    client._max_api_pages = getattr(config.discovery, "max_api_pages", 100)

    return client
