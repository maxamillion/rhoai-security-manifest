"""Analysis orchestrator that coordinates security analysis workflow."""

import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any

from ..api.container_catalog import ContainerCatalogClient, ContainerImage
from ..api.security_data import SecurityDataClient, ContainerSecurityInfo
from ..database.repository import (
    ReleaseRepository, ContainerRepository, VulnerabilityRepository
)
from ..database.models import SessionLocal
from .grading import SecurityGrader, SecurityGrade
from ..utils.logging import get_logger

logger = get_logger("analysis.orchestrator")


class AnalysisResult:
    """Container for analysis results."""
    
    def __init__(
        self,
        release_version: str,
        containers: List[Dict[str, Any]],
        summary: Dict[str, Any],
        metadata: Dict[str, Any]
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
        database_session_factory=SessionLocal
    ):
        """Initialize the orchestrator.
        
        Args:
            catalog_client: Container catalog API client
            security_client: Security data API client  
            grader: Security grading engine
            database_session_factory: Database session factory
        """
        self.catalog_client = catalog_client
        self.security_client = security_client
        self.grader = grader
        self.session_factory = database_session_factory
    
    async def analyze_release(
        self,
        release_version: str,
        force_refresh: bool = False,
        offline_mode: bool = False,
        container_filter: Optional[List[str]] = None,
        include_packages: bool = False
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
        await self._store_results(release_version, containers, security_analyses, graded_containers)
        
        # Step 5: Compile final results
        analysis_result = self._compile_results(
            release_version, containers, security_analyses, graded_containers, start_time
        )
        
        duration = (datetime.now() - start_time).total_seconds()
        logger.info(f"Analysis completed in {duration:.1f} seconds")
        
        return analysis_result
    
    async def _discover_containers(
        self,
        release_version: str,
        offline_mode: bool,
        force_refresh: bool,
        container_filter: Optional[List[str]]
    ) -> List[ContainerImage]:
        """Discover containers for the release."""
        if offline_mode:
            return self._load_cached_containers(release_version, container_filter)
        
        try:
            containers = await self.catalog_client.discover_rhoai_containers(
                release_version, container_filter
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
        self,
        release_version: str,
        container_filter: Optional[List[str]]
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
                    architecture="x86_64"  # Default assumption
                )
                containers.append(container)
            
            logger.info(f"Loaded {len(containers)} containers from cache")
            return containers
    
    async def _analyze_container_security(
        self,
        containers: List[ContainerImage],
        offline_mode: bool,
        force_refresh: bool,
        include_packages: bool
    ) -> List[ContainerSecurityInfo]:
        """Analyze security for all containers."""
        if offline_mode:
            return self._load_cached_security_data(containers)
        
        try:
            # Prepare container data for bulk analysis
            container_data = [
                {"name": c.name, "digest": c.digest}
                for c in containers
            ]
            
            security_analyses = await self.security_client.bulk_analyze_containers(
                container_data, include_packages
            )
            
            return security_analyses
            
        except Exception as e:
            logger.error(f"Security analysis failed: {e}")
            if not offline_mode:
                # Fallback to cached data
                logger.info("Falling back to cached security data")
                return self._load_cached_security_data(containers)
            raise
    
    def _load_cached_security_data(
        self,
        containers: List[ContainerImage]
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
                        container_name=container.name,
                        digest=container.digest
                    )
                    security_analyses.append(security_info)
                    continue
                
                # Load vulnerabilities
                vulnerabilities = vuln_repo.get_vulnerabilities_by_container(db_container.id)
                
                # Convert to API format (simplified)
                cve_data = []
                for vuln in vulnerabilities:
                    # Note: This is a simplified conversion
                    # In a real implementation, you'd need to map all fields properly
                    cve_data.append(type('CVEData', (), {
                        'cve_id': vuln.cve_id,
                        'severity': type('Severity', (), {'value': vuln.severity})(),
                        'cvss_score': vuln.cvss_score,
                        'description': vuln.description or "",
                        'published_date': datetime.now(),  # Simplified
                        'fixed_in_version': vuln.fixed_in_version
                    })())
                
                security_info = ContainerSecurityInfo(
                    container_name=container.name,
                    digest=container.digest,
                    vulnerabilities=cve_data,
                    packages_scanned=0,  # Not tracked in current DB schema
                    last_updated=db_container.last_scanned or datetime.now()
                )
                
                security_analyses.append(security_info)
        
        logger.info(f"Loaded cached security data for {len(security_analyses)} containers")
        return security_analyses
    
    def _grade_containers(
        self,
        security_analyses: List[ContainerSecurityInfo]
    ) -> List[Tuple[str, SecurityGrade, int, Dict[str, Any]]]:
        """Grade all containers."""
        graded_containers = []
        
        for security_info in security_analyses:
            grade, score, breakdown = self.grader.grade_container(security_info)
            graded_containers.append((
                security_info.container_name,
                grade,
                score,
                breakdown
            ))
        
        logger.info(f"Graded {len(graded_containers)} containers")
        return graded_containers
    
    async def _store_results(
        self,
        release_version: str,
        containers: List[ContainerImage],
        security_analyses: List[ContainerSecurityInfo],
        graded_containers: List[Tuple[str, SecurityGrade, int, Dict[str, Any]]]
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
                            security_grade=grade.value
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
                release_repo.update_container_count(
                    release.id, len(containers)
                )
                
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
        start_time: datetime
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
                "total_vulnerabilities": sum(security_info.vulnerability_summary.values()),
                "packages_scanned": security_info.packages_scanned,
                "last_scanned": security_info.last_updated.isoformat(),
                "grading_breakdown": breakdown
            }
            container_results.append(container_result)
        
        # Generate summary
        summary = self.grader.get_security_summary(graded_containers)
        summary.update({
            "containers_analyzed": len(containers),
            "analysis_duration_seconds": (datetime.now() - start_time).total_seconds()
        })
        
        # Build metadata
        metadata = {
            "release_version": release_version,
            "analysis_timestamp": datetime.now().isoformat(),
            "tool_version": "1.0.0",
            "containers_discovered": len(containers),
            "containers_analyzed": len(security_analyses)
        }
        
        return AnalysisResult(
            release_version=release_version,
            containers=container_results,
            summary=summary,
            metadata=metadata
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
                "security_posture": "unknown"
            },
            metadata={
                "release_version": release_version,
                "analysis_timestamp": datetime.now().isoformat(),
                "tool_version": "1.0.0",
                "containers_discovered": 0,
                "containers_analyzed": 0
            }
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
        grader=grader
    )