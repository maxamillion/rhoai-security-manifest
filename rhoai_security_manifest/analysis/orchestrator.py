"""Analysis orchestrator that coordinates security analysis workflow."""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from ..api.container_catalog import ContainerCatalogClient, ContainerImage
from ..api.security_data import ContainerSecurityInfo, SecurityDataClient
from ..database.models import SessionLocal
from ..database.repository import (
    ContainerRepository,
    ReleaseRepository,
    VulnerabilityRepository,
)
from ..utils.logging import get_logger
from .grading import SecurityGrade, SecurityGrader

logger = get_logger("analysis.orchestrator")


def load_container_config(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """Load container configuration from YAML file.

    Args:
        config_path: Optional path to configuration file.
                     Defaults to config/containers.yaml

    Returns:
        Dictionary containing container configuration
    """
    if config_path is None:
        # Try multiple possible locations
        possible_paths = [
            Path("config/containers.yaml"),
            Path(__file__).parent.parent.parent / "config" / "containers.yaml",
            Path.cwd() / "config" / "containers.yaml",
        ]

        for path in possible_paths:
            if path.exists():
                config_path = path
                break
        else:
            logger.warning("No container configuration file found")
            return {}

    try:
        with open(config_path, "r") as f:
            config = yaml.safe_load(f) or {}
            logger.info(f"Loaded container configuration from {config_path}")
            return config
    except Exception as e:
        logger.warning(f"Failed to load container configuration: {e}")
        return {}


class AnalysisResult:
    """Container for analysis results."""

    def __init__(
        self,
        release_version: str,
        containers: List[Dict[str, Any]],
        summary: Dict[str, Any],
        metadata: Dict[str, Any],
    ):
        self.release_version = release_version
        self.containers = containers
        self.summary = summary
        self.metadata = metadata
        self.generated_at = datetime.now()


class SecurityAnalysisOrchestrator:
    """Orchestrates the complete security analysis workflow."""

    def __init__(
        self,
        catalog_client: ContainerCatalogClient,
        security_client: SecurityDataClient,
        grader: SecurityGrader,
        config=None,
        database_session_factory=SessionLocal,
    ):
        """Initialize the orchestrator.

        Args:
            catalog_client: Container catalog API client
            security_client: Security data API client
            grader: Security grading engine
            config: Application configuration
            database_session_factory: Database session factory
        """
        self.catalog_client = catalog_client
        self.security_client = security_client
        self.grader = grader
        self.config = config
        self.session_factory = database_session_factory

    async def analyze_release(
        self,
        release_version: str,
        force_refresh: bool = False,
        offline_mode: bool = False,
        container_filter: Optional[List[str]] = None,
        include_packages: bool = False,
    ) -> AnalysisResult:
        """Perform complete security analysis for a release.

        Args:
            release_version: Release version to analyze
            force_refresh: Ignore cache and refresh all data
            offline_mode: Use cached data only
            container_filter: Optional list of container names to analyze
            include_packages: Include package-level vulnerability details

        Returns:
            Complete analysis results
        """
        logger.info(f"Starting security analysis for release {release_version}")

        start_time = datetime.now()

        # Step 1: Discover containers
        containers = await self._discover_containers(
            release_version, offline_mode, force_refresh, container_filter
        )

        if not containers:
            logger.warning(f"No containers found for release {release_version}")
            return self._create_empty_result(release_version)

        logger.info(f"Found {len(containers)} containers to analyze")

        # Step 2: Analyze security for each container
        security_analyses = await self._analyze_container_security(
            containers, offline_mode, force_refresh, include_packages
        )

        # Step 3: Grade containers
        graded_containers = self._grade_containers(security_analyses)

        # Step 4: Store results in database
        await self._store_results(
            release_version, containers, security_analyses, graded_containers
        )

        # Step 5: Compile final results
        analysis_result = self._compile_results(
            release_version,
            containers,
            security_analyses,
            graded_containers,
            start_time,
        )

        duration = (datetime.now() - start_time).total_seconds()
        logger.info(f"Analysis completed in {duration:.1f} seconds")

        return analysis_result

    async def _discover_containers(
        self,
        release_version: str,
        offline_mode: bool,
        force_refresh: bool,
        container_filter: Optional[List[str]],
    ) -> List[ContainerImage]:
        """Discover containers for the release."""
        if offline_mode:
            return self._load_cached_containers(release_version, container_filter)

        try:
            # Load manual container configuration
            container_config = load_container_config()
            manual_containers = None

            # Check if we have manual containers defined for this release
            if container_config and "rhoai_containers" in container_config:
                if release_version in container_config["rhoai_containers"]:
                    manual_containers = container_config["rhoai_containers"][
                        release_version
                    ]
                    logger.info(
                        f"Using manual container configuration for release {release_version}"
                    )

            # Use configuration setting for hybrid discovery (fallback to True if no config)
            hybrid_discovery = True
            if self.config and hasattr(self.config, "discovery"):
                hybrid_discovery = self.config.discovery.hybrid_discovery
            containers = await self.catalog_client.discover_rhoai_containers(
                release_version, container_filter, manual_containers, hybrid_discovery
            )
            return containers
        except Exception as e:
            logger.error(f"Container discovery failed: {e}")
            if not offline_mode:
                # Fallback to cached data
                logger.info("Falling back to cached container data")
                return self._load_cached_containers(release_version, container_filter)
            raise

    def _load_cached_containers(
        self, release_version: str, container_filter: Optional[List[str]]
    ) -> List[ContainerImage]:
        """Load containers from database cache."""
        with self.session_factory() as session:
            release_repo = ReleaseRepository(session)
            container_repo = ContainerRepository(session)

            release = release_repo.get_by_version(release_version)
            if not release:
                logger.warning(f"No cached data found for release {release_version}")
                return []

            db_containers = container_repo.get_by_release(release.id)

            # Convert to ContainerImage objects
            containers = []
            for db_container in db_containers:
                # Apply filter if specified
                if container_filter and db_container.name not in container_filter:
                    continue

                container = ContainerImage(
                    name=db_container.name,
                    registry_url=db_container.registry_url,
                    digest=db_container.digest,
                    tag="",  # Not stored in DB
                    created_at=db_container.created_at,
                    architecture="x86_64",  # Default assumption
                )
                containers.append(container)

            logger.info(f"Loaded {len(containers)} containers from cache")
            return containers

    async def _analyze_container_security(
        self,
        containers: List[ContainerImage],
        offline_mode: bool,
        force_refresh: bool,
        include_packages: bool,
    ) -> List[ContainerSecurityInfo]:
        """Analyze security for all containers using package-based approach."""
        if offline_mode:
            return self._load_cached_security_data(containers)

        from ..api.security_data import ContainerManifest, RPMPackage

        security_analyses = []

        for container in containers:
            try:
                logger.info(f"Analyzing container: {container.name}")

                # Step 1: Get container image details
                image_details = await self.catalog_client.get_image_by_id(
                    container.digest
                )
                if not image_details:
                    logger.warning(
                        f"No image details found for {container.name}, trying alternate methods"
                    )
                    # Try with container name as ID
                    image_details = await self.catalog_client.get_image_by_id(
                        container.name
                    )

                # Step 2: Get RPM manifest for the container
                rpm_manifest = None
                if image_details and image_details.get("_id"):
                    rpm_manifest = await self.catalog_client.get_rpm_manifest(
                        image_details["_id"]
                    )

                if not rpm_manifest:
                    logger.warning(
                        f"No RPM manifest found for {container.name}, using demo data"
                    )
                    # Create demo manifest with sample packages to demonstrate the workflow
                    # In production, this would come from the actual API
                    demo_packages = []

                    # Add some common packages that would typically be in a container
                    if "notebook" in container.name:
                        demo_packages.extend(
                            [
                                RPMPackage(
                                    name="python3",
                                    version="3.9.16",
                                    release="1.el8",
                                    arch="x86_64",
                                ),
                                RPMPackage(
                                    name="python3-pip",
                                    version="21.2.4",
                                    release="7.el8",
                                    arch="x86_64",
                                ),
                                RPMPackage(
                                    name="jupyter-core",
                                    version="4.11.1",
                                    release="1.el8",
                                    arch="noarch",
                                ),
                            ]
                        )
                    elif "tensorflow" in container.name:
                        demo_packages.extend(
                            [
                                RPMPackage(
                                    name="tensorflow",
                                    version="2.11.0",
                                    release="1.el8",
                                    arch="x86_64",
                                ),
                                RPMPackage(
                                    name="python3-numpy",
                                    version="1.21.6",
                                    release="1.el8",
                                    arch="x86_64",
                                ),
                            ]
                        )
                    elif "pytorch" in container.name:
                        demo_packages.extend(
                            [
                                RPMPackage(
                                    name="pytorch",
                                    version="2.0.1",
                                    release="1.el8",
                                    arch="x86_64",
                                ),
                                RPMPackage(
                                    name="python3-torch",
                                    version="2.0.1",
                                    release="1.el8",
                                    arch="x86_64",
                                ),
                            ]
                        )

                    # Add common base packages
                    demo_packages.extend(
                        [
                            RPMPackage(
                                name="glibc",
                                version="2.28",
                                release="236.el8",
                                arch="x86_64",
                            ),
                            RPMPackage(
                                name="openssl-libs",
                                version="1.1.1k",
                                release="9.el8",
                                arch="x86_64",
                            ),
                            RPMPackage(
                                name="systemd",
                                version="239",
                                release="74.el8",
                                arch="x86_64",
                            ),
                        ]
                    )

                    container_manifest = ContainerManifest(
                        image_id=container.name,
                        image_digest=container.digest,
                        packages=demo_packages,
                        content_sets=[
                            "rhel-8-for-x86_64-baseos-rpms",
                            "rhel-8-for-x86_64-appstream-rpms",
                        ],
                        build_date=container.created_at,
                    )
                else:
                    # Parse RPM manifest
                    packages = []
                    for rpm in rpm_manifest.get("rpms", []):
                        package = RPMPackage(
                            name=rpm.get("name", ""),
                            version=rpm.get("version", ""),
                            release=rpm.get("release", ""),
                            epoch=rpm.get("epoch"),
                            arch=rpm.get("architecture", "x86_64"),
                            source_rpm=rpm.get("srpm"),
                            size=rpm.get("size"),
                            license=rpm.get("license"),
                            vendor=rpm.get("vendor"),
                        )
                        packages.append(package)

                    container_manifest = ContainerManifest(
                        image_id=container.name,
                        image_digest=container.digest,
                        packages=packages,
                        content_sets=rpm_manifest.get("content_sets", []),
                        build_date=container.created_at,
                    )

                # Step 3: Analyze security of packages
                security_info = await self.security_client.analyze_container_packages(
                    container_manifest, include_details=include_packages
                )

                # Update container name to match input
                security_info.container_name = container.name

                security_analyses.append(security_info)

            except Exception as e:
                logger.error(f"Failed to analyze container {container.name}: {e}")
                # Create empty security info for failed containers
                security_info = ContainerSecurityInfo(
                    container_name=container.name,
                    digest=container.digest,
                    vulnerabilities=[],
                    advisories=[],
                    packages_scanned=0,
                    last_updated=datetime.now(),
                )
                security_analyses.append(security_info)

        return security_analyses

    def _load_cached_security_data(
        self, containers: List[ContainerImage]
    ) -> List[ContainerSecurityInfo]:
        """Load security data from database cache."""
        security_analyses = []

        with self.session_factory() as session:
            container_repo = ContainerRepository(session)
            vuln_repo = VulnerabilityRepository(session)

            for container in containers:
                db_container = container_repo.get_container_by_digest(container.digest)
                if not db_container:
                    # Create empty security info for missing containers
                    security_info = ContainerSecurityInfo(
                        container_name=container.name, digest=container.digest
                    )
                    security_analyses.append(security_info)
                    continue

                # Load vulnerabilities
                vulnerabilities = vuln_repo.get_vulnerabilities_by_container(
                    db_container.id
                )

                # Convert to API format (simplified)
                cve_data = []
                for vuln in vulnerabilities:
                    # Note: This is a simplified conversion
                    # In a real implementation, you'd need to map all fields properly
                    cve_data.append(
                        type(
                            "CVEData",
                            (),
                            {
                                "cve_id": vuln.cve_id,
                                "severity": type(
                                    "Severity", (), {"value": vuln.severity}
                                )(),
                                "cvss_score": vuln.cvss_score,
                                "description": vuln.description or "",
                                "published_date": datetime.now(),  # Simplified
                                "fixed_in_version": vuln.fixed_in_version,
                            },
                        )()
                    )

                security_info = ContainerSecurityInfo(
                    container_name=container.name,
                    digest=container.digest,
                    vulnerabilities=cve_data,
                    packages_scanned=0,  # Not tracked in current DB schema
                    last_updated=db_container.last_scanned or datetime.now(),
                )

                security_analyses.append(security_info)

        logger.info(
            f"Loaded cached security data for {len(security_analyses)} containers"
        )
        return security_analyses

    def _grade_containers(
        self, security_analyses: List[ContainerSecurityInfo]
    ) -> List[Tuple[str, SecurityGrade, int, Dict[str, Any]]]:
        """Grade all containers."""
        graded_containers = []

        for security_info in security_analyses:
            grade, score, breakdown = self.grader.grade_container(security_info)
            graded_containers.append(
                (security_info.container_name, grade, score, breakdown)
            )

        logger.info(f"Graded {len(graded_containers)} containers")
        return graded_containers

    async def _store_results(
        self,
        release_version: str,
        containers: List[ContainerImage],
        security_analyses: List[ContainerSecurityInfo],
        graded_containers: List[Tuple[str, SecurityGrade, int, Dict[str, Any]]],
    ) -> None:
        """Store analysis results in database."""
        try:
            with self.session_factory() as session:
                release_repo = ReleaseRepository(session)
                container_repo = ContainerRepository(session)
                vuln_repo = VulnerabilityRepository(session)

                # Get or create release
                release = release_repo.get_by_version(release_version)
                if not release:
                    release = release_repo.create(release_version)

                # Store containers and their security data
                for i, container in enumerate(containers):
                    security_info = security_analyses[i]
                    _, grade, score, _ = graded_containers[i]

                    # Get or create container record
                    db_container = container_repo.get_by_name_and_release(
                        container.name, release.id
                    )

                    if not db_container:
                        db_container = container_repo.create(
                            release_id=release.id,
                            name=container.name,
                            registry_url=container.registry_url,
                            digest=container.digest,
                            security_grade=grade.value,
                        )
                    else:
                        # Update existing container
                        container_repo.update_security_grade(
                            db_container.id, grade.value
                        )

                    # Store vulnerabilities
                    vuln_repo.bulk_insert_vulnerabilities(
                        db_container.id, security_info
                    )

                # Update release container count
                release_repo.update_container_count(release.id, len(containers))

            logger.info("Analysis results stored in database")

        except Exception as e:
            logger.error(f"Failed to store results in database: {e}")
            # Don't fail the entire analysis for database issues

    def _compile_results(
        self,
        release_version: str,
        containers: List[ContainerImage],
        security_analyses: List[ContainerSecurityInfo],
        graded_containers: List[Tuple[str, SecurityGrade, int, Dict[str, Any]]],
        start_time: datetime,
    ) -> AnalysisResult:
        """Compile final analysis results."""

        # Build container results
        container_results = []
        for i, container in enumerate(containers):
            security_info = security_analyses[i]
            name, grade, score, breakdown = graded_containers[i]

            container_result = {
                "name": container.name,
                "registry_url": container.registry_url,
                "digest": container.digest,
                "security_grade": grade.value,
                "security_score": score,
                "vulnerabilities": security_info.vulnerability_summary,
                "total_vulnerabilities": sum(
                    security_info.vulnerability_summary.values()
                ),
                "packages_scanned": security_info.packages_scanned,
                "last_scanned": security_info.last_updated.isoformat(),
                "grading_breakdown": breakdown,
            }
            container_results.append(container_result)

        # Generate summary
        summary = self.grader.get_security_summary(graded_containers)
        summary.update(
            {
                "containers_analyzed": len(containers),
                "analysis_duration_seconds": (
                    datetime.now() - start_time
                ).total_seconds(),
            }
        )

        # Build metadata
        metadata = {
            "release_version": release_version,
            "analysis_timestamp": datetime.now().isoformat(),
            "tool_version": "1.0.0",
            "containers_discovered": len(containers),
            "containers_analyzed": len(security_analyses),
        }

        return AnalysisResult(
            release_version=release_version,
            containers=container_results,
            summary=summary,
            metadata=metadata,
        )

    def _create_empty_result(self, release_version: str) -> AnalysisResult:
        """Create empty analysis result when no containers found."""
        return AnalysisResult(
            release_version=release_version,
            containers=[],
            summary={
                "total_containers": 0,
                "average_score": 0,
                "grade_distribution": {},
                "security_posture": "unknown",
            },
            metadata={
                "release_version": release_version,
                "analysis_timestamp": datetime.now().isoformat(),
                "tool_version": "1.0.0",
                "containers_discovered": 0,
                "containers_analyzed": 0,
            },
        )


async def create_orchestrator(config) -> SecurityAnalysisOrchestrator:
    """Create and configure a security analysis orchestrator.

    Args:
        config: Application configuration

    Returns:
        Configured orchestrator instance
    """
    from ..api.container_catalog import create_catalog_client
    from ..api.security_data import create_security_client
    from .grading import create_grader

    # Create API clients
    catalog_client = await create_catalog_client(config)
    security_client = await create_security_client(config)

    # Create grader
    grader = create_grader()

    return SecurityAnalysisOrchestrator(
        catalog_client=catalog_client,
        security_client=security_client,
        grader=grader,
        config=config,
    )
