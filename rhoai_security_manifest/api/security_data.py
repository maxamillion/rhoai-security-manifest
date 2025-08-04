"""Red Hat Security Data API client for CVE and vulnerability information."""

import asyncio
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import httpx
from pydantic import BaseModel, Field

from ..utils.logging import get_logger

logger = get_logger("api.security_data")


class Severity(str, Enum):
    """CVE severity levels."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    UNKNOWN = "Unknown"


class VulnerabilityStatus(str, Enum):
    """Vulnerability status."""

    NEW = "new"
    EXISTING = "existing"
    RESOLVED = "resolved"
    IGNORED = "ignored"


class CVEData(BaseModel):
    """CVE vulnerability data."""

    cve_id: str
    severity: Severity
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    description: str
    published_date: datetime
    modified_date: Optional[datetime] = None
    fixed_in_version: Optional[str] = None
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    rhsa_id: Optional[str] = None  # Red Hat Security Advisory ID


class SecurityAdvisory(BaseModel):
    """Red Hat Security Advisory data."""

    advisory_id: str
    title: str
    severity: Severity
    published_date: datetime
    updated_date: Optional[datetime] = None
    summary: str
    affected_packages: List[str] = Field(default_factory=list)
    cves: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)


class ContainerSecurityInfo(BaseModel):
    """Security information for a container."""

    container_name: str
    digest: str
    vulnerabilities: List[CVEData] = Field(default_factory=list)
    advisories: List[SecurityAdvisory] = Field(default_factory=list)
    packages_scanned: int = 0
    last_updated: datetime = Field(default_factory=datetime.now)

    @property
    def vulnerability_summary(self) -> Dict[str, int]:
        """Get vulnerability count by severity."""
        summary = {severity.value: 0 for severity in Severity}
        for vuln in self.vulnerabilities:
            summary[vuln.severity.value] += 1
        return summary


class SecurityDataClient:
    """Client for Red Hat Security Data API (CSAF)."""

    def __init__(
        self,
        base_url: str = "https://access.redhat.com/hydra/rest/",
        timeout: int = 30,
        max_retries: int = 3,
        max_concurrent: int = 5,
    ):
        """Initialize the security data client.

        Args:
            base_url: Base URL for Red Hat Security Data API
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

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self._client.aclose()

    async def close(self):
        """Close the HTTP client."""
        await self._client.aclose()

    async def get_cve_details(self, cve_id: str) -> Optional[CVEData]:
        """Get detailed information for a specific CVE.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2023-12345")

        Returns:
            CVE details or None if not found
        """
        async with self._semaphore:
            url = urljoin(self.base_url, f"security/cve/{cve_id}")

            try:
                response = await self._make_request("GET", url)
                data = response.json()
                return self._parse_cve_data(data)
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404:
                    logger.warning(f"CVE not found: {cve_id}")
                    return None
                raise

    async def search_cves(
        self,
        query: str,
        after_date: Optional[datetime] = None,
        severity: Optional[Severity] = None,
        limit: int = 100,
    ) -> List[CVEData]:
        """Search for CVEs matching criteria.

        Args:
            query: Search query string
            after_date: Only return CVEs published after this date
            severity: Filter by severity level
            limit: Maximum number of results

        Returns:
            List of matching CVEs
        """
        async with self._semaphore:
            url = urljoin(self.base_url, "security/cve")

            params = {"q": query, "limit": min(limit, 1000)}

            if after_date:
                params["after"] = after_date.isoformat()

            if severity:
                params["severity"] = severity.value

            response = await self._make_request("GET", url, params=params)
            data = response.json()

            cves = []
            for item in data.get("data", []):
                try:
                    cve = self._parse_cve_data(item)
                    cves.append(cve)
                except Exception as e:
                    logger.warning(f"Failed to parse CVE data: {e}")
                    continue

            return cves

    async def get_container_vulnerabilities(
        self, container_name: str, container_digest: str, include_packages: bool = False
    ) -> ContainerSecurityInfo:
        """Get vulnerability information for a container.

        Args:
            container_name: Name of the container
            container_digest: Container digest/SHA
            include_packages: Whether to include package-level details

        Returns:
            Container security information
        """
        logger.info(f"Analyzing security for container: {container_name}")

        # Try different approaches to get vulnerability data
        vulnerabilities = []
        advisories = []
        packages_scanned = 0

        try:
            # Method 1: Direct container lookup
            container_vulns = await self._get_container_direct(container_digest)
            if container_vulns:
                vulnerabilities.extend(container_vulns)
        except Exception as e:
            logger.debug(f"Direct container lookup failed: {e}")

        try:
            # Method 2: Search by container name and related packages
            name_based_vulns = await self._search_by_container_name(container_name)
            vulnerabilities.extend(name_based_vulns)
        except Exception as e:
            logger.debug(f"Name-based search failed: {e}")

        try:
            # Method 3: Get security advisories
            advisories = await self._get_related_advisories(container_name)
        except Exception as e:
            logger.debug(f"Advisory lookup failed: {e}")

        # Deduplicate vulnerabilities by CVE ID
        seen_cves = set()
        unique_vulns = []
        for vuln in vulnerabilities:
            if vuln.cve_id not in seen_cves:
                unique_vulns.append(vuln)
                seen_cves.add(vuln.cve_id)

        return ContainerSecurityInfo(
            container_name=container_name,
            digest=container_digest,
            vulnerabilities=unique_vulns,
            advisories=advisories,
            packages_scanned=packages_scanned,
            last_updated=datetime.now(),
        )

    async def get_security_advisory(
        self, advisory_id: str
    ) -> Optional[SecurityAdvisory]:
        """Get details for a Red Hat Security Advisory.

        Args:
            advisory_id: Advisory ID (e.g., "RHSA-2023:1234")

        Returns:
            Advisory details or None if not found
        """
        async with self._semaphore:
            url = urljoin(self.base_url, f"security/advisory/{advisory_id}")

            try:
                response = await self._make_request("GET", url)
                data = response.json()
                return self._parse_advisory_data(data)
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404:
                    logger.warning(f"Advisory not found: {advisory_id}")
                    return None
                raise

    async def bulk_analyze_containers(
        self, containers: List[Dict[str, str]], include_packages: bool = False
    ) -> List[ContainerSecurityInfo]:
        """Analyze multiple containers in parallel.

        Args:
            containers: List of container dicts with 'name' and 'digest' keys
            include_packages: Whether to include package-level details

        Returns:
            List of container security information
        """
        logger.info(f"Bulk analyzing {len(containers)} containers")

        # Create tasks for parallel analysis
        tasks = [
            self.get_container_vulnerabilities(
                container["name"], container["digest"], include_packages
            )
            for container in containers
        ]

        # Execute in parallel with concurrency limits
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results and handle exceptions
        security_infos = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(
                    f"Failed to analyze container {containers[i]['name']}: {result}"
                )
                # Create empty result for failed containers
                security_infos.append(
                    ContainerSecurityInfo(
                        container_name=containers[i]["name"],
                        digest=containers[i]["digest"],
                    )
                )
            else:
                security_infos.append(result)

        return security_infos

    async def _get_container_direct(self, digest: str) -> List[CVEData]:
        """Attempt direct container vulnerability lookup."""
        # This would be the ideal case, but may not be available
        # in the current Red Hat APIs
        return []

    async def _search_by_container_name(self, container_name: str) -> List[CVEData]:
        """Search for vulnerabilities by container name patterns."""
        # Search for CVEs mentioning this container or related packages
        search_terms = [
            container_name,
            f"openshift {container_name}",
            f"rhoai {container_name}",
        ]

        all_cves = []
        for term in search_terms:
            try:
                cves = await self.search_cves(term, limit=50)
                all_cves.extend(cves)
            except Exception as e:
                logger.debug(f"Search failed for term '{term}': {e}")
                continue

        return all_cves

    async def _get_related_advisories(
        self, container_name: str
    ) -> List[SecurityAdvisory]:
        """Get security advisories related to the container."""
        async with self._semaphore:
            url = urljoin(self.base_url, "security/advisory")

            params = {"q": f"openshift {container_name}", "limit": 50}

            try:
                response = await self._make_request("GET", url, params=params)
                data = response.json()

                advisories = []
                for item in data.get("data", []):
                    try:
                        advisory = self._parse_advisory_data(item)
                        advisories.append(advisory)
                    except Exception as e:
                        logger.warning(f"Failed to parse advisory data: {e}")
                        continue

                return advisories
            except Exception as e:
                logger.debug(f"Advisory search failed: {e}")
                return []

    async def _make_request(
        self, method: str, url: str, params: Optional[Dict] = None, **kwargs
    ) -> httpx.Response:
        """Make HTTP request with retry logic."""
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
                    delay = 2**attempt + (attempt * 0.1)
                    logger.warning(
                        f"Request failed (attempt {attempt + 1}/{self.max_retries + 1}): {e}"
                    )
                    await asyncio.sleep(delay)
                else:
                    logger.error(
                        f"Request failed after {self.max_retries + 1} attempts: {e}"
                    )

        raise last_exception

    def _parse_cve_data(self, data: Dict[str, Any]) -> CVEData:
        """Parse CVE data from API response."""
        cve_id = data.get("cve", "")

        # Parse severity
        severity_str = data.get("severity", "Unknown").title()
        try:
            severity = Severity(severity_str)
        except ValueError:
            severity = Severity.UNKNOWN

        # Parse CVSS score
        cvss_score = data.get("cvss_score") or data.get("cvss3_score")
        if isinstance(cvss_score, str):
            try:
                cvss_score = float(cvss_score)
            except ValueError:
                cvss_score = None

        # Parse dates
        published_str = data.get("public_date") or data.get("published_date")
        published_date = datetime.now()
        if published_str:
            try:
                published_date = datetime.fromisoformat(
                    published_str.replace("Z", "+00:00")
                )
            except (ValueError, AttributeError):
                pass

        modified_date = None
        modified_str = data.get("modified_date")
        if modified_str:
            try:
                modified_date = datetime.fromisoformat(
                    modified_str.replace("Z", "+00:00")
                )
            except (ValueError, AttributeError):
                pass

        return CVEData(
            cve_id=cve_id,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=data.get("cvss_vector"),
            description=data.get("description", ""),
            published_date=published_date,
            modified_date=modified_date,
            fixed_in_version=data.get("fixed_in_version"),
            package_name=data.get("package_name"),
            package_version=data.get("package_version"),
            references=data.get("references", []),
            rhsa_id=data.get("rhsa"),
        )

    def _parse_advisory_data(self, data: Dict[str, Any]) -> SecurityAdvisory:
        """Parse security advisory data from API response."""
        advisory_id = data.get("name", "")

        # Parse severity
        severity_str = data.get("severity", "Unknown").title()
        try:
            severity = Severity(severity_str)
        except ValueError:
            severity = Severity.UNKNOWN

        # Parse dates
        published_str = data.get("published_date")
        published_date = datetime.now()
        if published_str:
            try:
                published_date = datetime.fromisoformat(
                    published_str.replace("Z", "+00:00")
                )
            except (ValueError, AttributeError):
                pass

        updated_date = None
        updated_str = data.get("updated_date")
        if updated_str:
            try:
                updated_date = datetime.fromisoformat(
                    updated_str.replace("Z", "+00:00")
                )
            except (ValueError, AttributeError):
                pass

        return SecurityAdvisory(
            advisory_id=advisory_id,
            title=data.get("title", ""),
            severity=severity,
            published_date=published_date,
            updated_date=updated_date,
            summary=data.get("summary", ""),
            affected_packages=data.get("affected_packages", []),
            cves=data.get("cves", []),
            references=data.get("references", []),
        )


async def create_security_client(config) -> SecurityDataClient:
    """Create and configure a security data client.

    Args:
        config: Application configuration

    Returns:
        Configured security data client
    """
    return SecurityDataClient(
        timeout=config.api.timeout,
        max_retries=config.api.max_retries,
        max_concurrent=min(config.api.max_concurrent_requests, 5),  # Be conservative
    )
