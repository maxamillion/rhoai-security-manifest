"""Data access layer for database operations."""

from datetime import datetime, timedelta
from typing import List, Optional

from sqlalchemy import and_, desc, func
from sqlalchemy.orm import Session, joinedload

from .models import Container, Package, Release, Vulnerability


class ReleaseRepository:
    """Repository for Release model operations."""

    def __init__(self, session: Session):
        self.session = session

    def get_by_version(self, version: str) -> Optional[Release]:
        """Get a release by version string."""
        return self.session.query(Release).filter(Release.version == version).first()

    def create(self, version: str) -> Release:
        """Create a new release."""
        release = Release(version=version)
        self.session.add(release)
        self.session.commit()
        return release

    def get_all(self) -> List[Release]:
        """Get all releases ordered by version."""
        return self.session.query(Release).order_by(desc(Release.created_at)).all()

    def update_container_count(self, release_id: int, count: int) -> None:
        """Update the container count for a release."""
        release = self.session.query(Release).filter(Release.id == release_id).first()
        if release:
            release.container_count = count
            release.last_updated = datetime.utcnow()
            self.session.commit()

    def delete_old_releases(self, days_to_keep: int = 180) -> int:
        """Delete releases older than specified days.

        Args:
            days_to_keep: Number of days to retain data

        Returns:
            Number of releases deleted
        """
        cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)
        deleted_count = (
            self.session.query(Release)
            .filter(Release.created_at < cutoff_date)
            .delete()
        )
        self.session.commit()
        return deleted_count


class ContainerRepository:
    """Repository for Container model operations."""

    def __init__(self, session: Session):
        self.session = session

    def get_by_release(self, release_id: int) -> List[Container]:
        """Get all containers for a release."""
        return (
            self.session.query(Container)
            .filter(Container.release_id == release_id)
            .options(joinedload(Container.vulnerabilities))
            .all()
        )

    def get_by_name_and_release(
        self, name: str, release_id: int
    ) -> Optional[Container]:
        """Get a container by name and release."""
        return (
            self.session.query(Container)
            .filter(and_(Container.name == name, Container.release_id == release_id))
            .first()
        )

    def create(
        self,
        release_id: int,
        name: str,
        registry_url: str,
        digest: str,
        security_grade: Optional[str] = None,
    ) -> Container:
        """Create a new container."""
        container = Container(
            release_id=release_id,
            name=name,
            registry_url=registry_url,
            digest=digest,
            security_grade=security_grade,
        )
        self.session.add(container)
        self.session.commit()
        return container

    def update_security_grade(self, container_id: int, grade: str) -> None:
        """Update the security grade for a container."""
        container = (
            self.session.query(Container).filter(Container.id == container_id).first()
        )
        if container:
            container.security_grade = grade
            container.last_scanned = datetime.utcnow()
            self.session.commit()

    def get_containers_by_grade(self, release_id: int) -> dict:
        """Get container count by security grade for a release."""
        results = (
            self.session.query(
                Container.security_grade, func.count(Container.id).label("count")
            )
            .filter(Container.release_id == release_id)
            .group_by(Container.security_grade)
            .all()
        )
        return {grade or "Unknown": count for grade, count in results}


class VulnerabilityRepository:
    """Repository for Vulnerability model operations."""

    def __init__(self, session: Session):
        self.session = session

    def get_by_container(self, container_id: int) -> List[Vulnerability]:
        """Get all vulnerabilities for a container."""
        return (
            self.session.query(Vulnerability)
            .filter(Vulnerability.container_id == container_id)
            .order_by(desc(Vulnerability.cvss_score))
            .all()
        )

    def create(
        self,
        container_id: int,
        cve_id: str,
        severity: str,
        cvss_score: Optional[float] = None,
        description: Optional[str] = None,
        fixed_in_version: Optional[str] = None,
        status: str = "new",
    ) -> Vulnerability:
        """Create a new vulnerability record."""
        vulnerability = Vulnerability(
            container_id=container_id,
            cve_id=cve_id,
            severity=severity,
            cvss_score=cvss_score,
            description=description,
            fixed_in_version=fixed_in_version,
            status=status,
        )
        self.session.add(vulnerability)
        self.session.commit()
        return vulnerability

    def get_by_severity(self, container_id: int, severity: str) -> List[Vulnerability]:
        """Get vulnerabilities by severity for a container."""
        return (
            self.session.query(Vulnerability)
            .filter(
                and_(
                    Vulnerability.container_id == container_id,
                    Vulnerability.severity == severity,
                )
            )
            .all()
        )

    def get_severity_counts(self, container_id: int) -> dict:
        """Get vulnerability count by severity for a container."""
        results = (
            self.session.query(
                Vulnerability.severity, func.count(Vulnerability.id).label("count")
            )
            .filter(Vulnerability.container_id == container_id)
            .group_by(Vulnerability.severity)
            .all()
        )
        return {severity: count for severity, count in results}

    def mark_as_resolved(self, container_id: int, cve_ids: List[str]) -> int:
        """Mark vulnerabilities as resolved.

        Args:
            container_id: Container ID
            cve_ids: List of CVE IDs to mark as resolved

        Returns:
            Number of vulnerabilities updated
        """
        updated_count = (
            self.session.query(Vulnerability)
            .filter(
                and_(
                    Vulnerability.container_id == container_id,
                    Vulnerability.cve_id.in_(cve_ids),
                )
            )
            .update({"status": "resolved"})
        )
        self.session.commit()
        return updated_count

    def get_new_vulnerabilities(
        self, container_id: int, since_date: datetime
    ) -> List[Vulnerability]:
        """Get new vulnerabilities since a specific date."""
        return (
            self.session.query(Vulnerability)
            .filter(
                and_(
                    Vulnerability.container_id == container_id,
                    Vulnerability.first_seen >= since_date,
                    Vulnerability.status == "new",
                )
            )
            .all()
        )


class PackageRepository:
    """Repository for Package model operations."""

    def __init__(self, session: Session):
        self.session = session

    def get_by_container(self, container_id: int) -> List[Package]:
        """Get all packages for a container."""
        return (
            self.session.query(Package)
            .filter(Package.container_id == container_id)
            .order_by(Package.name)
            .all()
        )

    def create(
        self,
        container_id: int,
        name: str,
        version: str,
        vulnerability_count: int = 0,
    ) -> Package:
        """Create a new package record."""
        package = Package(
            container_id=container_id,
            name=name,
            version=version,
            vulnerability_count=vulnerability_count,
        )
        self.session.add(package)
        self.session.commit()
        return package

    def update_vulnerability_count(self, package_id: int, count: int) -> None:
        """Update vulnerability count for a package."""
        package = self.session.query(Package).filter(Package.id == package_id).first()
        if package:
            package.vulnerability_count = count
            self.session.commit()

    def get_vulnerable_packages(self, container_id: int) -> List[Package]:
        """Get packages with vulnerabilities for a container."""
        return (
            self.session.query(Package)
            .filter(
                and_(
                    Package.container_id == container_id,
                    Package.vulnerability_count > 0,
                )
            )
            .order_by(desc(Package.vulnerability_count))
            .all()
        )
