"""Red Hat Container Catalog API client."""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin

import httpx
from pydantic import BaseModel, Field

from ..utils.logging import get_logger

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
        max_concurrent: int = 10
    ):
        """Initialize the catalog client.
        
        Args:
            base_url: Base URL for the Container Catalog API
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            max_concurrent: Maximum concurrent requests
        """
        self.base_url = base_url.rstrip('/') + '/'
        self.timeout = timeout
        self.max_retries = max_retries
        self.max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)
        
        # Configure HTTP client
        self._client = httpx.AsyncClient(
            timeout=timeout,
            limits=httpx.Limits(max_connections=max_concurrent * 2)
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
    
    async def search_containers(
        self,
        query: str,
        page: int = 1,
        page_size: int = 100,
        filter_params: Optional[Dict[str, str]] = None
    ) -> CatalogSearchResult:
        """Search for containers in the catalog.
        
        Args:
            query: Search query string
            page: Page number (1-based)
            page_size: Number of results per page
            filter_params: Additional filter parameters
            
        Returns:
            Search results with container metadata
            
        Raises:
            httpx.HTTPError: On API request failures
        """
        async with self._semaphore:
            url = urljoin(self.base_url, "repositories")
            
            params = {
                "q": query,
                "page": page,
                "page_size": min(page_size, 100),  # API limit
            }
            
            if filter_params:
                params.update(filter_params)
            
            logger.debug(f"Searching containers: query='{query}', page={page}")
            
            response = await self._make_request("GET", url, params=params)
            data = response.json()
            
            # Parse response data
            images = []
            for item in data.get("data", []):
                try:
                    image = self._parse_container_data(item)
                    images.append(image)
                except Exception as e:
                    logger.warning(f"Failed to parse container data: {e}")
                    continue
            
            return CatalogSearchResult(
                total=data.get("total", 0),
                page=page,
                page_size=page_size,
                images=images
            )
    
    async def get_container_details(self, container_id: str) -> Optional[ContainerImage]:
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
        filter_names: Optional[List[str]] = None
    ) -> List[ContainerImage]:
        """Discover all RHOAI containers for a specific release.
        
        Args:
            release_version: RHOAI release version (e.g., "2.8.0")
            filter_names: Optional list of container names to filter by
            
        Returns:
            List of container images for the release
        """
        logger.info(f"Discovering RHOAI containers for release {release_version}")
        
        # Search patterns for RHOAI containers
        search_patterns = [
            f"rhoai {release_version}",
            f"openshift-ai {release_version}",
            f"rhods {release_version}",  # Legacy name
        ]
        
        all_containers = []
        seen_digests = set()
        
        for pattern in search_patterns:
            try:
                page = 1
                while True:
                    result = await self.search_containers(
                        query=pattern,
                        page=page,
                        page_size=100,
                        filter_params={
                            "vendor": "redhat",
                            "architecture": "x86_64"
                        }
                    )
                    
                    # Filter containers
                    for container in result.images:
                        # Avoid duplicates
                        if container.digest in seen_digests:
                            continue
                        
                        # Apply name filter if specified
                        if filter_names and not any(name in container.name.lower() for name in filter_names):
                            continue
                        
                        # Verify this is actually for the requested release
                        if self._is_release_match(container, release_version):
                            all_containers.append(container)
                            seen_digests.add(container.digest)
                    
                    # Check if we have more pages
                    if len(result.images) < result.page_size:
                        break
                    
                    page += 1
                    
            except Exception as e:
                logger.warning(f"Failed to search with pattern '{pattern}': {e}")
                continue
        
        logger.info(f"Found {len(all_containers)} containers for release {release_version}")
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
    
    async def _make_request(
        self,
        method: str,
        url: str,
        params: Optional[Dict] = None,
        **kwargs
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
            try:
                response = await self._client.request(
                    method, url, params=params, **kwargs
                )
                response.raise_for_status()
                return response
                
            except httpx.HTTPError as e:
                last_exception = e
                
                if attempt < self.max_retries:
                    # Calculate backoff delay
                    delay = 2 ** attempt + (attempt * 0.1)
                    logger.warning(
                        f"Request failed (attempt {attempt + 1}/{self.max_retries + 1}): {e}"
                    )
                    logger.debug(f"Retrying in {delay:.1f} seconds...")
                    await asyncio.sleep(delay)
                else:
                    logger.error(f"Request failed after {self.max_retries + 1} attempts: {e}")
        
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
        name = data.get("name", "")
        registry_url = data.get("registry_url", "")
        
        # Extract digest - may be in different locations
        digest = (
            data.get("digest") or 
            data.get("image_digest") or
            data.get("content_sets", [{}])[0].get("digest", "")
        )
        
        # Extract tag
        tag = data.get("tag", "latest")
        
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
        size_bytes = data.get("size_bytes")
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
            labels=labels
        )
    
    def _is_release_match(self, container: ContainerImage, release_version: str) -> bool:
        """Check if container matches the specified release version.
        
        Args:
            container: Container image to check
            release_version: Target release version
            
        Returns:
            True if container matches the release
        """
        # Check tag
        if release_version in container.tag:
            return True
        
        # Check registry URL
        if release_version in container.registry_url:
            return True
        
        # Check labels
        for key, value in container.labels.items():
            if release_version in str(value):
                return True
        
        # Default: assume match if no clear indication otherwise
        return True


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
        max_concurrent=config.api.max_concurrent_requests
    )