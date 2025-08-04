"""Configuration management for the security manifest tool."""

import os
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field, validator


class DatabaseConfig(BaseModel):
    """Database configuration settings."""

    url: str = Field(
        default="sqlite:///security_manifest.db", description="Database connection URL"
    )
    retention_days: int = Field(
        default=180, ge=30, le=365, description="Data retention period in days"
    )
    backup_enabled: bool = Field(
        default=True, description="Enable automatic database backups"
    )
    backup_retention_days: int = Field(
        default=30, ge=7, le=90, description="Backup retention period"
    )


class APIConfig(BaseModel):
    """API configuration settings."""

    container_catalog_base_url: str = Field(
        default="https://catalog.redhat.com/api/containers/v1/",
        description="Red Hat Container Catalog API base URL",
    )
    security_data_base_url: str = Field(
        default="https://access.redhat.com/hydra/rest/securitydata/",
        description="Red Hat Security Data API base URL",
    )
    timeout: int = Field(
        default=30, ge=10, le=300, description="API request timeout in seconds"
    )
    max_retries: int = Field(
        default=3, ge=1, le=10, description="Maximum number of retry attempts"
    )
    retry_backoff: float = Field(
        default=1.0, ge=0.1, le=10.0, description="Retry backoff multiplier"
    )
    max_concurrent_requests: int = Field(
        default=10, ge=1, le=50, description="Maximum concurrent API requests"
    )
    rate_limit_per_minute: int = Field(
        default=100, ge=10, le=1000, description="Rate limit per minute"
    )


class CacheConfig(BaseModel):
    """Cache configuration settings."""

    enabled: bool = Field(default=True, description="Enable API response caching")
    directory: Path = Field(default=Path("cache"), description="Cache directory path")
    max_size_mb: int = Field(
        default=500, ge=100, le=5000, description="Maximum cache size in MB"
    )
    cleanup_interval_hours: int = Field(
        default=24, ge=1, le=168, description="Cache cleanup interval"
    )


class ReportConfig(BaseModel):
    """Report generation configuration settings."""

    output_directory: Path = Field(
        default=Path("security_reports"), description="Report output directory"
    )
    include_packages_by_default: bool = Field(
        default=False, description="Include package details by default"
    )
    html_template_theme: str = Field(default="default", description="HTML report theme")
    max_report_size_mb: int = Field(
        default=100, ge=10, le=1000, description="Maximum report size in MB"
    )


class DiscoveryConfig(BaseModel):
    """Container discovery configuration settings."""

    hybrid_discovery: bool = Field(
        default=True, description="Enable hybrid discovery (manual + API)"
    )
    api_discovery_enabled: bool = Field(
        default=True, description="Enable API-based container discovery"
    )
    max_search_pages: int = Field(
        default=100, ge=10, le=500, description="Maximum API search pages per pattern"
    )
    search_timeout_minutes: int = Field(
        default=30, ge=5, le=120, description="Maximum time for container discovery"
    )


class SecurityConfig(BaseModel):
    """Security grading configuration settings."""

    use_redhat_grades: bool = Field(
        default=True, description="Prefer Red Hat security grades when available"
    )
    critical_weight: int = Field(
        default=20, ge=1, le=50, description="Weight for critical vulnerabilities"
    )
    high_weight: int = Field(
        default=10, ge=1, le=25, description="Weight for high severity vulnerabilities"
    )
    medium_weight: int = Field(
        default=5, ge=1, le=15, description="Weight for medium severity vulnerabilities"
    )
    low_weight: int = Field(
        default=1, ge=1, le=5, description="Weight for low severity vulnerabilities"
    )
    unpatched_penalty: int = Field(
        default=10,
        ge=1,
        le=25,
        description="Additional penalty for unpatched vulnerabilities",
    )
    age_factor_weight: int = Field(
        default=5, ge=1, le=15, description="Weight for vulnerability age factor"
    )


class LoggingConfig(BaseModel):
    """Logging configuration settings."""

    level: str = Field(default="INFO", description="Logging level")
    file_enabled: bool = Field(default=True, description="Enable file logging")
    file_path: Path = Field(
        default=Path("logs/security_manifest.log"), description="Log file path"
    )
    max_file_size_mb: int = Field(
        default=10, ge=1, le=100, description="Maximum log file size in MB"
    )
    backup_count: int = Field(
        default=5, ge=1, le=20, description="Number of log file backups to keep"
    )
    format: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        description="Log message format",
    )

    @validator("level")
    def validate_log_level(cls, v):
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Invalid log level. Must be one of: {valid_levels}")
        return v.upper()


class Config(BaseModel):
    """Main configuration container."""

    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    api: APIConfig = Field(default_factory=APIConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    reports: ReportConfig = Field(default_factory=ReportConfig)
    discovery: DiscoveryConfig = Field(default_factory=DiscoveryConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    # Global settings
    debug: bool = Field(default=False, description="Enable debug mode")
    quiet: bool = Field(default=False, description="Suppress non-error output")
    color_output: bool = Field(
        default=True, description="Enable colored terminal output"
    )
    progress_bars: bool = Field(default=True, description="Show progress bars")


class ConfigManager:
    """Configuration management class."""

    def __init__(self, config_file: Optional[Path] = None):
        """Initialize configuration manager.

        Args:
            config_file: Optional path to configuration file
        """
        self.config_file = config_file or self._find_config_file()
        self._config: Optional[Config] = None

    def _find_config_file(self) -> Optional[Path]:
        """Find configuration file in standard locations."""
        possible_locations = [
            Path.cwd() / "security_manifest.yaml",
            Path.cwd() / "security_manifest.yml",
            Path.cwd() / ".security_manifest.yaml",
            Path.cwd() / ".security_manifest.yml",
            Path.home() / ".config" / "security_manifest" / "config.yaml",
            Path.home() / ".security_manifest.yaml",
        ]

        for location in possible_locations:
            if location.exists():
                return location

        return None

    def load_config(self) -> Config:
        """Load configuration from file and environment variables.

        Returns:
            Loaded configuration object
        """
        if self._config is not None:
            return self._config

        config_data = {}

        # Load from file if it exists
        if self.config_file and self.config_file.exists():
            config_data = self._load_from_file(self.config_file)

        # Override with environment variables
        config_data = self._load_from_environment(config_data)

        # Create config object
        self._config = Config(**config_data)

        # Ensure directories exist
        self._ensure_directories()

        return self._config

    def _load_from_file(self, config_file: Path) -> dict:
        """Load configuration from YAML file.

        Args:
            config_file: Path to configuration file

        Returns:
            Configuration dictionary
        """
        try:
            import yaml

            with open(config_file) as f:
                return yaml.safe_load(f) or {}
        except ImportError:
            # yaml not available, skip file loading
            return {}
        except Exception as e:
            raise ValueError(f"Failed to load config file {config_file}: {e}") from e

    def _load_from_environment(self, config_data: dict) -> dict:
        """Load configuration from environment variables.

        Args:
            config_data: Existing configuration data

        Returns:
            Updated configuration dictionary
        """
        env_mappings = {
            # Database settings
            "RHOAI_DATABASE_URL": ["database", "url"],
            "RHOAI_DATABASE_RETENTION_DAYS": ["database", "retention_days"],
            # API settings
            "RHOAI_CONTAINER_CATALOG_URL": ["api", "container_catalog_base_url"],
            "RHOAI_SECURITY_DATA_URL": ["api", "security_data_base_url"],
            "RHOAI_API_TIMEOUT": ["api", "timeout"],
            "RHOAI_MAX_RETRIES": ["api", "max_retries"],
            "RHOAI_MAX_CONCURRENT_REQUESTS": ["api", "max_concurrent_requests"],
            # Cache settings
            "RHOAI_CACHE_ENABLED": ["cache", "enabled"],
            "RHOAI_CACHE_DIRECTORY": ["cache", "directory"],
            "RHOAI_CACHE_MAX_SIZE_MB": ["cache", "max_size_mb"],
            # Report settings
            "RHOAI_REPORTS_DIRECTORY": ["reports", "output_directory"],
            "RHOAI_INCLUDE_PACKAGES": ["reports", "include_packages_by_default"],
            # Discovery settings
            "RHOAI_HYBRID_DISCOVERY": ["discovery", "hybrid_discovery"],
            "RHOAI_API_DISCOVERY_ENABLED": ["discovery", "api_discovery_enabled"],
            "RHOAI_MAX_SEARCH_PAGES": ["discovery", "max_search_pages"],
            # Logging settings
            "RHOAI_LOG_LEVEL": ["logging", "level"],
            "RHOAI_LOG_FILE": ["logging", "file_path"],
            # Global settings
            "RHOAI_DEBUG": ["debug"],
            "RHOAI_QUIET": ["quiet"],
            "RHOAI_NO_COLOR": ["color_output"],
        }

        for env_var, path in env_mappings.items():
            value = os.environ.get(env_var)
            if value is not None:
                # Convert string values to appropriate types
                value = self._convert_env_value(value)

                # Set nested value
                current = config_data
                for key in path[:-1]:
                    if key not in current:
                        current[key] = {}
                    current = current[key]

                # Handle special cases
                if env_var == "RHOAI_NO_COLOR":
                    current[path[-1]] = not self._convert_to_bool(value)
                else:
                    current[path[-1]] = value

        return config_data

    def _convert_env_value(self, value: str):
        """Convert environment variable string to appropriate type."""
        # Boolean values
        if value.lower() in ("true", "false"):
            return value.lower() == "true"

        # Integer values
        try:
            return int(value)
        except ValueError:
            pass

        # Float values
        try:
            return float(value)
        except ValueError:
            pass

        # Path values (if they look like paths)
        if "/" in value or "\\" in value:
            return Path(value)

        # String values
        return value

    def _convert_to_bool(self, value) -> bool:
        """Convert various value types to boolean."""
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ("true", "1", "yes", "on")
        return bool(value)

    def _ensure_directories(self) -> None:
        """Ensure required directories exist."""
        if self._config is None:
            return

        directories = [
            self._config.cache.directory,
            self._config.reports.output_directory,
            self._config.logging.file_path.parent,
        ]

        for directory in directories:
            try:
                directory.mkdir(parents=True, exist_ok=True)
            except Exception:
                # Don't fail configuration loading for directory creation issues
                pass

    def save_config(self, config_file: Optional[Path] = None) -> None:
        """Save current configuration to file.

        Args:
            config_file: Optional path to save configuration
        """
        if self._config is None:
            raise ValueError("No configuration loaded")

        save_path = config_file or self.config_file or Path("security_manifest.yaml")

        try:
            import yaml

            with open(save_path, "w") as f:
                yaml.safe_dump(self._config.dict(), f, default_flow_style=False)
        except ImportError as e:
            raise ValueError("PyYAML is required to save configuration files") from e

    @property
    def config(self) -> Config:
        """Get current configuration, loading if necessary."""
        if self._config is None:
            return self.load_config()
        return self._config


# Global configuration manager instance
_config_manager: Optional[ConfigManager] = None


def get_config(config_file: Optional[Path] = None) -> Config:
    """Get application configuration.

    Args:
        config_file: Optional path to configuration file

    Returns:
        Configuration object
    """
    global _config_manager

    if _config_manager is None:
        _config_manager = ConfigManager(config_file)

    return _config_manager.load_config()


def reset_config() -> None:
    """Reset global configuration manager (mainly for testing)."""
    global _config_manager
    _config_manager = None
