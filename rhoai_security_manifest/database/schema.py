"""Database schema management and migrations."""

import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from sqlalchemy import text

from .models import Base, create_database_engine, create_tables

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Database schema and migration management."""

    def __init__(self, database_url: str = "sqlite:///security_manifest.db"):
        """Initialize database manager.

        Args:
            database_url: Database connection URL
        """
        self.database_url = database_url
        self.engine = create_database_engine(database_url)

    def initialize_database(self) -> None:
        """Initialize database with all tables."""
        try:
            logger.info("Initializing database schema...")
            create_tables(self.engine)
            self._create_indexes()
            logger.info("Database schema initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise

    def _create_indexes(self) -> None:
        """Create database indexes for performance."""
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_containers_release_id ON containers(release_id)",
            "CREATE INDEX IF NOT EXISTS idx_containers_name ON containers(name)",
            "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_container_id ON vulnerabilities(container_id)",
            "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve_id ON vulnerabilities(cve_id)",
            "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity)",
            "CREATE INDEX IF NOT EXISTS idx_packages_container_id ON packages(container_id)",
            "CREATE INDEX IF NOT EXISTS idx_packages_name ON packages(name)",
            "CREATE INDEX IF NOT EXISTS idx_releases_version ON releases(version)",
        ]

        with self.engine.connect() as conn:
            for index_sql in indexes:
                try:
                    conn.execute(text(index_sql))
                    logger.debug(f"Created index: {index_sql}")
                except Exception as e:
                    logger.warning(f"Failed to create index: {e}")
            conn.commit()

    def backup_database(self, backup_path: Optional[Path] = None) -> Path:
        """Create a backup of the database.

        Args:
            backup_path: Optional path for backup file

        Returns:
            Path to the backup file
        """
        if "sqlite" not in self.database_url:
            raise NotImplementedError("Backup only supported for SQLite databases")

        # Extract database file path from URL
        db_path = Path(self.database_url.replace("sqlite:///", ""))

        if backup_path is None:
            backup_path = (
                db_path.parent
                / f"{db_path.stem}_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
            )

        if db_path.exists():
            import shutil

            shutil.copy2(db_path, backup_path)
            logger.info(f"Database backed up to: {backup_path}")
        else:
            logger.warning(f"Database file not found: {db_path}")

        return backup_path

    def check_database_health(self) -> dict:
        """Check database health and return statistics.

        Returns:
            Dictionary with database health information
        """
        health_info = {
            "status": "unknown",
            "tables": {},
            "indexes": [],
            "size_mb": 0,
        }

        try:
            with self.engine.connect() as conn:
                # Check if tables exist
                tables_query = """
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name NOT LIKE 'sqlite_%'
                """
                tables = conn.execute(text(tables_query)).fetchall()

                for (table_name,) in tables:
                    count_query = f"SELECT COUNT(*) FROM {table_name}"
                    count = conn.execute(text(count_query)).scalar()
                    health_info["tables"][table_name] = count

                # Check indexes
                indexes_query = """
                SELECT name FROM sqlite_master 
                WHERE type='index' AND name NOT LIKE 'sqlite_%'
                """
                indexes = conn.execute(text(indexes_query)).fetchall()
                health_info["indexes"] = [idx[0] for idx in indexes]

                # Get database size (SQLite specific)
                if "sqlite" in self.database_url:
                    db_path = Path(self.database_url.replace("sqlite:///", ""))
                    if db_path.exists():
                        health_info["size_mb"] = round(
                            db_path.stat().st_size / (1024 * 1024), 2
                        )

                health_info["status"] = "healthy"
                logger.info("Database health check completed successfully")

        except Exception as e:
            health_info["status"] = f"error: {e}"
            logger.error(f"Database health check failed: {e}")

        return health_info

    def cleanup_old_data(self, days_to_keep: int = 180) -> dict:
        """Clean up old data from the database.

        Args:
            days_to_keep: Number of days to retain data

        Returns:
            Dictionary with cleanup statistics
        """
        from .models import SessionLocal
        from .repository import ReleaseRepository

        cleanup_stats = {
            "releases_deleted": 0,
            "containers_deleted": 0,
            "vulnerabilities_deleted": 0,
            "packages_deleted": 0,
        }

        try:
            with SessionLocal() as session:
                repo = ReleaseRepository(session)

                # Count related records before deletion
                from datetime import datetime, timedelta

                cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)

                # Get count of records to be deleted
                old_releases = session.execute(
                    text("SELECT COUNT(*) FROM releases WHERE created_at < :cutoff"),
                    {"cutoff": cutoff_date},
                ).scalar()

                if old_releases > 0:
                    # Count related records
                    related_containers = session.execute(
                        text(
                            """
                        SELECT COUNT(*) FROM containers c
                        JOIN releases r ON c.release_id = r.id
                        WHERE r.created_at < :cutoff
                        """
                        ),
                        {"cutoff": cutoff_date},
                    ).scalar()

                    related_vulnerabilities = session.execute(
                        text(
                            """
                        SELECT COUNT(*) FROM vulnerabilities v
                        JOIN containers c ON v.container_id = c.id
                        JOIN releases r ON c.release_id = r.id
                        WHERE r.created_at < :cutoff
                        """
                        ),
                        {"cutoff": cutoff_date},
                    ).scalar()

                    related_packages = session.execute(
                        text(
                            """
                        SELECT COUNT(*) FROM packages p
                        JOIN containers c ON p.container_id = c.id
                        JOIN releases r ON c.release_id = r.id
                        WHERE r.created_at < :cutoff
                        """
                        ),
                        {"cutoff": cutoff_date},
                    ).scalar()

                    # Delete old releases (cascading will handle related records)
                    deleted_releases = repo.delete_old_releases(days_to_keep)

                    cleanup_stats.update(
                        {
                            "releases_deleted": deleted_releases,
                            "containers_deleted": related_containers,
                            "vulnerabilities_deleted": related_vulnerabilities,
                            "packages_deleted": related_packages,
                        }
                    )

                logger.info(f"Cleanup completed: {cleanup_stats}")

        except Exception as e:
            logger.error(f"Database cleanup failed: {e}")
            raise

        return cleanup_stats

    def validate_schema(self) -> bool:
        """Validate that the database schema matches the expected structure.

        Returns:
            True if schema is valid, False otherwise
        """
        try:
            # Get expected tables from models
            expected_tables = set(Base.metadata.tables.keys())

            with self.engine.connect() as conn:
                # Get actual tables from database
                tables_query = """
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name NOT LIKE 'sqlite_%'
                """
                actual_tables = set(
                    row[0] for row in conn.execute(text(tables_query)).fetchall()
                )

                if expected_tables != actual_tables:
                    missing = expected_tables - actual_tables
                    extra = actual_tables - expected_tables

                    if missing:
                        logger.error(f"Missing tables: {missing}")
                    if extra:
                        logger.warning(f"Extra tables: {extra}")

                    return False

                logger.info("Database schema validation passed")
                return True

        except Exception as e:
            logger.error(f"Schema validation failed: {e}")
            return False


def get_database_manager(database_url: Optional[str] = None) -> DatabaseManager:
    """Get a database manager instance.

    Args:
        database_url: Optional database URL, defaults to SQLite

    Returns:
        DatabaseManager instance
    """
    if database_url is None:
        database_url = "sqlite:///security_manifest.db"

    return DatabaseManager(database_url)
