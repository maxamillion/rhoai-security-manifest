"""Database models for the security manifest tool."""

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    REAL,
    TEXT,
    TIMESTAMP,
    ForeignKey,
    Integer,
    JSON,
    create_engine,
    func,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
    sessionmaker,
)


class Base(DeclarativeBase):
    """Base class for all database models."""

    pass


class ProductListing(Base):
    """Model for cached Product Listings API data."""

    __tablename__ = "product_listings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    product_name: Mapped[str] = mapped_column(TEXT, nullable=False)
    product_id: Mapped[Optional[str]] = mapped_column(TEXT)
    vendor: Mapped[str] = mapped_column(TEXT, nullable=False, default="Red Hat")
    deployment_methods: Mapped[Optional[str]] = mapped_column(TEXT)  # JSON serialized list
    functional_categories: Mapped[Optional[str]] = mapped_column(TEXT)  # JSON serialized list
    operator_bundles: Mapped[Optional[str]] = mapped_column(TEXT)  # JSON serialized operator bundle data
    description: Mapped[Optional[str]] = mapped_column(TEXT)
    documentation_url: Mapped[Optional[str]] = mapped_column(TEXT)
    support_url: Mapped[Optional[str]] = mapped_column(TEXT)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP, nullable=False, default=func.now()
    )
    last_updated: Mapped[datetime] = mapped_column(
        TIMESTAMP, nullable=False, default=func.now(), onupdate=func.now()
    )
    cache_expires_at: Mapped[datetime] = mapped_column(TIMESTAMP, nullable=False)

    def __repr__(self) -> str:
        return f"<ProductListing(id={self.id}, product='{self.product_name}', vendor='{self.vendor}')>"


class Release(Base):
    """Model for OpenShift AI releases."""

    __tablename__ = "releases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    version: Mapped[str] = mapped_column(TEXT, unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP, nullable=False, default=func.now()
    )
    container_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_updated: Mapped[datetime] = mapped_column(
        TIMESTAMP, nullable=False, default=func.now(), onupdate=func.now()
    )

    # Relationships
    containers: Mapped[list["Container"]] = relationship(
        "Container", back_populates="release", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Release(id={self.id}, version='{self.version}', containers={self.container_count})>"


class Container(Base):
    """Model for container images in releases."""

    __tablename__ = "containers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    release_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("releases.id"), nullable=False
    )
    name: Mapped[str] = mapped_column(TEXT, nullable=False)
    registry_url: Mapped[str] = mapped_column(TEXT, nullable=False)
    digest: Mapped[str] = mapped_column(TEXT, nullable=False)
    security_grade: Mapped[Optional[str]] = mapped_column(TEXT)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP, nullable=False, default=func.now()
    )
    last_scanned: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP)
    
    # Product Listings integration fields
    source_method: Mapped[Optional[str]] = mapped_column(TEXT)  # "product_listings", "manual", "search"
    operator_bundle_id: Mapped[Optional[str]] = mapped_column(TEXT)  # Reference to operator bundle
    product_version: Mapped[Optional[str]] = mapped_column(TEXT)  # RHOAI version correlation
    categories: Mapped[Optional[str]] = mapped_column(TEXT)  # JSON serialized list of categories

    # Relationships
    release: Mapped["Release"] = relationship("Release", back_populates="containers")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        "Vulnerability", back_populates="container", cascade="all, delete-orphan"
    )
    packages: Mapped[list["Package"]] = relationship(
        "Package", back_populates="container", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Container(id={self.id}, name='{self.name}', grade='{self.security_grade}')>"


class Vulnerability(Base):
    """Model for vulnerabilities found in containers."""

    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    container_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("containers.id"), nullable=False
    )
    cve_id: Mapped[str] = mapped_column(TEXT, nullable=False)
    severity: Mapped[str] = mapped_column(TEXT, nullable=False)
    cvss_score: Mapped[Optional[float]] = mapped_column(REAL)
    description: Mapped[Optional[str]] = mapped_column(TEXT)
    fixed_in_version: Mapped[Optional[str]] = mapped_column(TEXT)
    first_seen: Mapped[datetime] = mapped_column(
        TIMESTAMP, nullable=False, default=func.now()
    )
    status: Mapped[str] = mapped_column(
        TEXT, nullable=False, default="new"
    )  # 'new', 'existing', 'resolved'

    # Relationships
    container: Mapped["Container"] = relationship(
        "Container", back_populates="vulnerabilities"
    )

    def __repr__(self) -> str:
        return f"<Vulnerability(id={self.id}, cve='{self.cve_id}', severity='{self.severity}')>"


class Package(Base):
    """Model for packages within container images."""

    __tablename__ = "packages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    container_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("containers.id"), nullable=False
    )
    name: Mapped[str] = mapped_column(TEXT, nullable=False)
    version: Mapped[str] = mapped_column(TEXT, nullable=False)
    vulnerability_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Relationships
    container: Mapped["Container"] = relationship(
        "Container", back_populates="packages"
    )

    def __repr__(self) -> str:
        return f"<Package(id={self.id}, name='{self.name}', version='{self.version}')>"


# Database session factory
SessionLocal = sessionmaker()


def create_database_engine(database_url: str = "sqlite:///security_manifest.db"):
    """Create and configure the database engine.

    Args:
        database_url: Database connection URL

    Returns:
        SQLAlchemy engine instance
    """
    engine = create_engine(
        database_url,
        echo=False,  # Set to True for SQL debugging
        pool_pre_ping=True,
        connect_args={"check_same_thread": False} if "sqlite" in database_url else {},
    )

    # Configure session factory
    SessionLocal.configure(bind=engine)

    return engine


def create_tables(engine):
    """Create all database tables.

    Args:
        engine: SQLAlchemy engine instance
    """
    Base.metadata.create_all(bind=engine)
