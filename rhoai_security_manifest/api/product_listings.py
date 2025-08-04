"""Red Hat Container Catalog Product Listings API client."""

import asyncio
from datetime import datetime
from typing import Any, Optional
from urllib.parse import urljoin

import httpx
from pydantic import BaseModel, Field

from ..utils.http_debug import debug_http_request
from ..utils.logging import get_logger

logger = get_logger("api.product_listings")


class OperatorBundle(BaseModel):
    """Operator bundle information from product listing."""

    package: str
    channel: str
    ocp_version: str
    capabilities: list[str] = Field(default_factory=list)
    valid_subscription: list[str] = Field(default_factory=list)
    csv_name: Optional[str] = None
    csv_version: Optional[str] = None
    bundle_path: Optional[str] = None


class ProductListing(BaseModel):
    """Product listing information from Red Hat Catalog."""

    product_name: str
    product_id: Optional[str] = None
    vendor: str = "Red Hat"
    deployment_methods: list[str] = Field(default_factory=list)
    functional_categories: list[str] = Field(default_factory=list)
    operator_bundles: list[OperatorBundle] = Field(default_factory=list)
    description: Optional[str] = None
    documentation_url: Optional[str] = None
    support_url: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.now)
    last_updated: datetime = Field(default_factory=datetime.now)


class ContainerRepository(BaseModel):
    """Container repository derived from product listing."""

    namespace: str
    repository: str
    registry: str = "registry.redhat.io"
    source_bundle: Optional[str] = None
    ocp_versions: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)


class ProductListingsClient:
    """Client for Red Hat Container Catalog Product Listings API."""

    def __init__(
        self,
        base_url: str = "https://catalog.redhat.com/api/containers/v1/",
        timeout: int = 30,
        max_retries: int = 3,
        max_concurrent: int = 5,
    ):
        """Initialize the product listings client.

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

        # Configure HTTP client
        self._client = httpx.AsyncClient(
            timeout=timeout,
            limits=httpx.Limits(max_connections=max_concurrent * 2),
            headers={
                "User-Agent": "rhoai-security-manifest/1.0.0",
                "Accept": "application/json",
            },
        )

        # Cache for product listings to avoid repeated API calls
        self._cache = {}
        self._cache_ttl = 3600  # 1 hour

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self._client.aclose()

    async def close(self):
        """Close the HTTP client."""
        await self._client.aclose()

    async def get_openshift_ai_product(
        self, force_refresh: bool = False
    ) -> Optional[ProductListing]:
        """Get Red Hat OpenShift AI product listing.

        Args:
            force_refresh: Ignore cache and fetch fresh data

        Returns:
            Product listing for OpenShift AI or None if not found
        """
        cache_key = "openshift_ai_product"

        # Check cache first unless force refresh
        if not force_refresh and cache_key in self._cache:
            cache_entry = self._cache[cache_key]
            if (datetime.now() - cache_entry["timestamp"]).seconds < self._cache_ttl:
                logger.debug("Using cached OpenShift AI product listing")
                return cache_entry["data"]

        logger.info("Fetching OpenShift AI product listing from API")

        async with self._semaphore:
            url = urljoin(self.base_url, "product-listings")
            params = {"filter": 'name=="Red Hat OpenShift AI"', "page_size": 10}

            try:
                response = await self._make_request("GET", url, params=params)
                data = response.json()

                # Parse the response
                products = data.get("data", [])
                if not products:
                    logger.warning("No OpenShift AI product found in catalog")
                    return None

                # Take the first matching product
                product_data = products[0]
                product_listing = self._parse_product_listing(product_data)

                # Cache the result
                self._cache[cache_key] = {
                    "data": product_listing,
                    "timestamp": datetime.now(),
                }

                logger.info(
                    f"Found OpenShift AI product with {len(product_listing.operator_bundles)} operator bundles"
                )
                return product_listing

            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404:
                    logger.warning("OpenShift AI product not found in catalog")
                    return None
                raise
            except Exception as e:
                logger.error(f"Failed to fetch OpenShift AI product listing: {e}")
                raise

    async def extract_container_repositories(
        self, product_listing: ProductListing
    ) -> list[ContainerRepository]:
        """Extract container repositories from product listing.

        Args:
            product_listing: Product listing containing operator bundles

        Returns:
            List of container repositories derived from operator bundles
        """
        repositories = []

        logger.info(
            f"Extracting container repositories from {len(product_listing.operator_bundles)} operator bundles"
        )

        for bundle in product_listing.operator_bundles:
            # Extract repository information from operator bundle
            container_repos = await self._resolve_bundle_containers(bundle)
            repositories.extend(container_repos)

        # Remove duplicates while preserving order
        unique_repos = []
        seen = set()
        for repo in repositories:
            repo_key = f"{repo.namespace}/{repo.repository}"
            if repo_key not in seen:
                unique_repos.append(repo)
                seen.add(repo_key)

        logger.info(f"Extracted {len(unique_repos)} unique container repositories")
        return unique_repos

    async def map_version_to_containers(
        self, product_listing: ProductListing, rhoai_version: str
    ) -> list[ContainerRepository]:
        """Map RHOAI version to specific container repositories.

        Args:
            product_listing: Product listing with operator bundles
            rhoai_version: RHOAI version (e.g., "2.19.0")

        Returns:
            List of container repositories for the specific version
        """
        all_repos = await self.extract_container_repositories(product_listing)

        # For now, return all repositories as version mapping logic
        # would need additional API calls or version correlation data
        # TODO: Implement version-specific filtering when API provides this data

        logger.info(
            f"Mapped {len(all_repos)} containers for RHOAI version {rhoai_version}"
        )
        return all_repos

    async def _resolve_bundle_containers(
        self, bundle: OperatorBundle
    ) -> list[ContainerRepository]:
        """Resolve operator bundle to actual container repositories.

        Args:
            bundle: Operator bundle information

        Returns:
            List of container repositories for this bundle
        """
        repositories = []

        # Map known operator packages to container repositories
        container_mappings = {
            "rhods-operator": [
                # Core RHOAI operator containers
                ContainerRepository(
                    namespace="rhoai",
                    repository="rhods-operator-rhel8",
                    source_bundle=bundle.package,
                    ocp_versions=[bundle.ocp_version],
                    categories=["operator"],
                ),
                ContainerRepository(
                    namespace="rhoai",
                    repository="rhods-operator-bundle",
                    source_bundle=bundle.package,
                    ocp_versions=[bundle.ocp_version],
                    categories=["operator"],
                ),
                # Dashboard and core components
                ContainerRepository(
                    namespace="rhoai",
                    repository="odh-dashboard-rhel8",
                    source_bundle=bundle.package,
                    ocp_versions=[bundle.ocp_version],
                    categories=["dashboard"],
                ),
                ContainerRepository(
                    namespace="rhoai",
                    repository="odh-notebook-controller-rhel8",
                    source_bundle=bundle.package,
                    ocp_versions=[bundle.ocp_version],
                    categories=["notebook", "controller"],
                ),
                # ML Pipelines components
                ContainerRepository(
                    namespace="rhoai",
                    repository="odh-ml-pipelines-api-server-rhel8",
                    source_bundle=bundle.package,
                    ocp_versions=[bundle.ocp_version],
                    categories=["pipelines", "api"],
                ),
                ContainerRepository(
                    namespace="rhoai",
                    repository="odh-ml-pipelines-persistenceagent-rhel8",
                    source_bundle=bundle.package,
                    ocp_versions=[bundle.ocp_version],
                    categories=["pipelines"],
                ),
                ContainerRepository(
                    namespace="rhoai",
                    repository="odh-ml-pipelines-scheduledworkflow-rhel8",
                    source_bundle=bundle.package,
                    ocp_versions=[bundle.ocp_version],
                    categories=["pipelines"],
                ),
                ContainerRepository(
                    namespace="rhoai",
                    repository="odh-ml-pipelines-viewercontroller-rhel8",
                    source_bundle=bundle.package,
                    ocp_versions=[bundle.ocp_version],
                    categories=["pipelines"],
                ),
                # KServe components
                ContainerRepository(
                    namespace="rhoai",
                    repository="odh-kserve-controller-rhel8",
                    source_bundle=bundle.package,
                    ocp_versions=[bundle.ocp_version],
                    categories=["serving", "kserve"],
                ),
                ContainerRepository(
                    namespace="rhoai",
                    repository="odh-kserve-agent-rhel8",
                    source_bundle=bundle.package,
                    ocp_versions=[bundle.ocp_version],
                    categories=["serving", "kserve"],
                ),
                ContainerRepository(
                    namespace="rhoai",
                    repository="odh-kserve-router-rhel8",
                    source_bundle=bundle.package,
                    ocp_versions=[bundle.ocp_version],
                    categories=["serving", "kserve"],
                ),
                # ModelMesh components
                ContainerRepository(
                    namespace="rhoai",
                    repository="odh-modelmesh-rhel8",
                    source_bundle=bundle.package,
                    ocp_versions=[bundle.ocp_version],
                    categories=["serving", "modelmesh"],
                ),
                ContainerRepository(
                    namespace="rhoai",
                    repository="odh-modelmesh-controller-rhel8",
                    source_bundle=bundle.package,
                    ocp_versions=[bundle.ocp_version],
                    categories=["serving", "modelmesh"],
                ),
                # Serving runtimes
                ContainerRepository(
                    namespace="rhoai",
                    repository="odh-pytorch-rhel8",
                    source_bundle=bundle.package,
                    ocp_versions=[bundle.ocp_version],
                    categories=["runtime", "pytorch"],
                ),
                ContainerRepository(
                    namespace="rhoai",
                    repository="odh-tensorflow-rhel8",
                    source_bundle=bundle.package,
                    ocp_versions=[bundle.ocp_version],
                    categories=["runtime", "tensorflow"],
                ),
                ContainerRepository(
                    namespace="rhoai",
                    repository="odh-triton-rhel8",
                    source_bundle=bundle.package,
                    ocp_versions=[bundle.ocp_version],
                    categories=["runtime", "triton"],
                ),
                # Notebook images
                ContainerRepository(
                    namespace="rhoai",
                    repository="odh-generic-data-science-notebook-rhel8",
                    source_bundle=bundle.package,
                    ocp_versions=[bundle.ocp_version],
                    categories=["notebook", "datascience"],
                ),
                ContainerRepository(
                    namespace="rhoai",
                    repository="odh-minimal-notebook-rhel8",
                    source_bundle=bundle.package,
                    ocp_versions=[bundle.ocp_version],
                    categories=["notebook", "minimal"],
                ),
                ContainerRepository(
                    namespace="rhoai",
                    repository="odh-pytorch-notebook-rhel8",
                    source_bundle=bundle.package,
                    ocp_versions=[bundle.ocp_version],
                    categories=["notebook", "pytorch"],
                ),
                ContainerRepository(
                    namespace="rhoai",
                    repository="odh-tensorflow-notebook-rhel8",
                    source_bundle=bundle.package,
                    ocp_versions=[bundle.ocp_version],
                    categories=["notebook", "tensorflow"],
                ),
                # TrustyAI components
                ContainerRepository(
                    namespace="rhoai",
                    repository="odh-trustyai-service-rhel8",
                    source_bundle=bundle.package,
                    ocp_versions=[bundle.ocp_version],
                    categories=["ai", "trustyai"],
                ),
                ContainerRepository(
                    namespace="rhoai",
                    repository="odh-trustyai-service-operator-controller-rhel8",
                    source_bundle=bundle.package,
                    ocp_versions=[bundle.ocp_version],
                    categories=["ai", "trustyai", "operator"],
                ),
            ]
        }

        # Get containers for this bundle package
        if bundle.package in container_mappings:
            repositories.extend(container_mappings[bundle.package])
            logger.debug(
                f"Mapped {len(container_mappings[bundle.package])} containers for bundle {bundle.package}"
            )
        else:
            logger.warning(
                f"No container mapping found for bundle package: {bundle.package}"
            )

        return repositories

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

        for attempt in range(self.max_retries + 1):
            with debug_http_request(method, url, params) as debug_ctx:
                try:
                    response = await self._client.request(
                        method, url, params=params, **kwargs
                    )
                    response.raise_for_status()

                    debug_ctx.log_response(response)
                    return response

                except httpx.HTTPError as e:
                    last_exception = e

                    if attempt < self.max_retries:
                        delay = 2**attempt + (attempt * 0.1)
                        logger.debug(
                            f"Request failed (attempt {attempt + 1}/{self.max_retries + 1}): {e}"
                        )
                        logger.debug(f"Retrying in {delay:.1f} seconds...")
                        await asyncio.sleep(delay)
                    else:
                        logger.error(
                            f"Request failed after {self.max_retries + 1} attempts: {e}"
                        )

        raise last_exception

    def _parse_product_listing(self, data: dict[str, Any]) -> ProductListing:
        """Parse product listing data from API response.

        Args:
            data: Raw product listing data from API

        Returns:
            Parsed product listing object
        """
        # Extract operator bundles
        operator_bundles = []
        for bundle_data in data.get("operator_bundles", []):
            bundle = OperatorBundle(
                package=bundle_data.get("package", ""),
                channel=bundle_data.get("channel", ""),
                ocp_version=bundle_data.get("ocp_version", ""),
                capabilities=bundle_data.get("capabilities", []),
                valid_subscription=bundle_data.get("valid_subscription", []),
                csv_name=bundle_data.get("csv_name"),
                csv_version=bundle_data.get("csv_version"),
                bundle_path=bundle_data.get("bundle_path"),
            )
            operator_bundles.append(bundle)

        return ProductListing(
            product_name=data.get("name", "Red Hat OpenShift AI"),
            product_id=data.get("id"),
            vendor=data.get("vendor", "Red Hat"),
            deployment_methods=data.get("deployment_method", []),
            functional_categories=data.get("functional_categories", []),
            operator_bundles=operator_bundles,
            description=data.get("description"),
            documentation_url=data.get("documentation_url"),
            support_url=data.get("support_url"),
        )


async def create_product_listings_client(config) -> ProductListingsClient:
    """Create and configure a product listings client.

    Args:
        config: Application configuration

    Returns:
        Configured product listings client
    """
    return ProductListingsClient(
        timeout=config.api.timeout,
        max_retries=config.api.max_retries,
        max_concurrent=min(config.api.max_concurrent_requests, 5),
    )
