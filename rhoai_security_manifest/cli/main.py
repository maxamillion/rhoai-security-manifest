"""Main CLI entry point for the security manifest tool."""

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from ..database.schema import get_database_manager
from ..utils.config import get_config, reset_config
from ..utils.logging import setup_logging
from .commands.cache import cache
from .commands.compare import compare
from .commands.generate import generate
from .commands.interactive import interactive
from .commands.validate import validate

# Create console for rich output
console = Console()


@click.group()
@click.option(
    "--config",
    type=click.Path(exists=True, path_type=Path),
    help="Path to configuration file",
)
@click.option("--debug/--no-debug", default=False, help="Enable debug mode")
@click.option("--quiet/--no-quiet", default=False, help="Suppress non-error output")
@click.option("--no-color", is_flag=True, help="Disable colored output")
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]),
    help="Set logging level",
)
@click.version_option(version="1.0.0", prog_name="osai-security-manifest")
@click.pass_context
def cli(
    ctx: click.Context,
    config: Optional[Path],
    debug: bool,
    quiet: bool,
    no_color: bool,
    log_level: Optional[str],
):
    """OpenShift AI Security Manifest Tool.

    Generate comprehensive security reports for Red Hat OpenShift AI releases.
    Query container vulnerabilities, assess security posture, and track changes
    over time.
    """
    # Ensure context object exists
    ctx.ensure_object(dict)

    # Reset config for testing or config file changes
    if config:
        reset_config()

    # Load configuration
    try:
        app_config = get_config(config)
        ctx.obj["config"] = app_config
    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        sys.exit(1)

    # Override config with CLI options
    if debug:
        app_config.debug = debug
    if log_level:
        app_config.logging.level = log_level
    if no_color:
        app_config.color_output = False
    if quiet:
        app_config.quiet = quiet

    # Set up logging
    try:
        logger = setup_logging(
            config=app_config,
            color_output=app_config.color_output and not no_color,
            quiet=quiet,
        )
        ctx.obj["logger"] = logger

        if debug:
            logger.debug("Debug mode enabled")
            logger.debug(f"Configuration loaded from: {config or 'defaults'}")

    except Exception as e:
        console.print(f"[red]Error setting up logging: {e}[/red]")
        sys.exit(1)

    # Initialize database
    try:
        db_manager = get_database_manager(app_config.database.url)
        db_manager.initialize_database()
        ctx.obj["db_manager"] = db_manager

        if debug:
            logger.debug(f"Database initialized: {app_config.database.url}")

    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        if not quiet:
            console.print(f"[red]Database initialization failed: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.pass_context
def version(ctx: click.Context):
    """Show version information."""
    from .. import __description__, __version__

    if not ctx.obj["config"].quiet:
        table = Table(title="OpenShift AI Security Manifest Tool")
        table.add_column("Component", style="cyan", no_wrap=True)
        table.add_column("Version", style="green")

        table.add_row("Application", __version__)
        table.add_row("Description", __description__)

        # Add dependency versions
        try:
            import click

            table.add_row("Click", click.__version__)
        except ImportError:
            pass

        try:
            import sqlalchemy

            table.add_row("SQLAlchemy", sqlalchemy.__version__)
        except ImportError:
            pass

        try:
            import httpx

            table.add_row("HTTPX", httpx.__version__)
        except ImportError:
            pass

        console.print(table)
    else:
        console.print(__version__)


@cli.command()
@click.option("--check-health", is_flag=True, help="Check database and system health")
@click.option("--show-config", is_flag=True, help="Show current configuration")
@click.pass_context
def status(ctx: click.Context, check_health: bool, show_config: bool):
    """Show application status and health information."""
    config = ctx.obj["config"]
    logger = ctx.obj["logger"]
    db_manager = ctx.obj["db_manager"]

    if show_config:
        _show_configuration(config)

    if check_health:
        _show_health_status(db_manager, logger, config.quiet)

    if not (check_health or show_config):
        # Default: show brief status
        _show_brief_status(config, db_manager)


def _show_configuration(config):
    """Display current configuration."""
    table = Table(title="Configuration")
    table.add_column("Setting", style="cyan", no_wrap=True)
    table.add_column("Value", style="green")

    # Database settings
    table.add_row("Database URL", str(config.database.url))
    table.add_row("Data Retention", f"{config.database.retention_days} days")

    # API settings
    table.add_row("API Timeout", f"{config.api.timeout}s")
    table.add_row("Max Retries", str(config.api.max_retries))
    table.add_row("Max Concurrent", str(config.api.max_concurrent_requests))

    # Cache settings
    table.add_row("Cache Enabled", str(config.cache.enabled))
    table.add_row("Cache Directory", str(config.cache.directory))

    # Report settings
    table.add_row("Output Directory", str(config.reports.output_directory))

    # Logging settings
    table.add_row("Log Level", config.logging.level)
    table.add_row("Log File", str(config.logging.file_path))

    console.print(table)


def _show_health_status(db_manager, logger, quiet: bool):
    """Display system health status."""
    if not quiet:
        console.print("\n[bold blue]System Health Check[/bold blue]")

    # Database health
    try:
        health_info = db_manager.check_database_health()

        if not quiet:
            table = Table(title="Database Health")
            table.add_column("Component", style="cyan")
            table.add_column("Status", style="green")
            table.add_column("Details")

            table.add_row("Database", health_info["status"], "")
            table.add_row("Size", f"{health_info['size_mb']} MB", "")

            for table_name, count in health_info["tables"].items():
                table.add_row(f"Table: {table_name}", "OK", f"{count} records")

            table.add_row("Indexes", f"{len(health_info['indexes'])} created", "")

            console.print(table)

        if health_info["status"] != "healthy":
            logger.warning(f"Database health check failed: {health_info['status']}")

    except Exception as e:
        logger.error(f"Health check failed: {e}")
        if not quiet:
            console.print(f"[red]Health check failed: {e}[/red]")


def _show_brief_status(config, db_manager):
    """Display brief application status."""
    try:
        health_info = db_manager.check_database_health()

        # Count total records
        total_releases = health_info["tables"].get("releases", 0)
        total_containers = health_info["tables"].get("containers", 0)
        total_vulnerabilities = health_info["tables"].get("vulnerabilities", 0)

        table = Table(title="Application Status")
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Value", style="green")

        table.add_row("Database Status", health_info["status"].title())
        table.add_row("Releases Tracked", str(total_releases))
        table.add_row("Containers Analyzed", str(total_containers))
        table.add_row("Vulnerabilities Found", str(total_vulnerabilities))
        table.add_row("Database Size", f"{health_info['size_mb']} MB")
        table.add_row("Cache Enabled", str(config.cache.enabled))

        console.print(table)

    except Exception as e:
        console.print(f"[red]Could not retrieve status: {e}[/red]")


# Add command groups
cli.add_command(generate)
cli.add_command(compare)
cli.add_command(cache)
cli.add_command(interactive)
cli.add_command(validate)


def main():
    """Main entry point for the CLI application."""
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        sys.exit(130)  # Standard exit code for Ctrl+C
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")
        # Only show traceback in debug mode
        import os

        if os.environ.get("RHOAI_DEBUG", "").lower() in ("true", "1"):
            import traceback

            console.print(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
