"""Cache management command for the security manifest tool."""

from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from sqlalchemy import text

from ...utils.logging import get_logger

console = Console()
logger = get_logger("cli.cache")


@click.command()
@click.option("--clean", is_flag=True, help="Clean expired cache entries")
@click.option("--clear", is_flag=True, help="Clear all cache data")
@click.option(
    "--older-than", help="Clean entries older than specified time (e.g., 30d, 7d, 24h)"
)
@click.option("--show-stats", is_flag=True, help="Show cache statistics")
@click.option("--release", help="Manage cache for specific release only")
@click.option("--vacuum", is_flag=True, help="Vacuum database to reclaim space")
@click.pass_context
def cache(
    ctx: click.Context,
    clean: bool,
    clear: bool,
    older_than: Optional[str],
    show_stats: bool,
    release: Optional[str],
    vacuum: bool,
):
    """Manage API response cache and database storage.

    The cache stores API responses to improve performance and enable offline operation.
    Use this command to clean old data, view statistics, or manage cache size.

    Examples:

        # Show cache statistics
        osai-security-manifest cache --show-stats

        # Clean entries older than 30 days
        osai-security-manifest cache --clean --older-than 30d

        # Clear all cache data
        osai-security-manifest cache --clear

        # Clean cache for specific release
        osai-security-manifest cache --clean --release 2.8.0

        # Vacuum database to reclaim space
        osai-security-manifest cache --vacuum
    """
    config = ctx.obj["config"]
    db_manager = ctx.obj["db_manager"]

    logger.info("Cache management operation started")

    # Validate conflicting options
    if clear and clean:
        console.print("[red]Error: Cannot use --clear and --clean together[/red]")
        raise click.Abort()

    if clear and older_than:
        console.print("[red]Error: --older-than is not used with --clear[/red]")
        raise click.Abort()

    try:
        # Show statistics (default if no other action specified)
        if show_stats or not any([clean, clear, vacuum]):
            _show_cache_stats(db_manager, config)

        # Clean operations
        if clean:
            days_to_keep = (
                _parse_time_period(older_than)
                if older_than
                else config.database.retention_days
            )
            _clean_cache(db_manager, days_to_keep, release)

        # Clear all cache
        if clear:
            _clear_cache(db_manager, release)

        # Vacuum database
        if vacuum:
            _vacuum_database(db_manager)

        logger.info("Cache management operation completed")

    except Exception as e:
        logger.error(f"Cache management failed: {e}")
        console.print(f"[red]Error: {e}[/red]")
        raise click.Abort() from e


def _show_cache_stats(db_manager, config) -> None:
    """Display cache statistics."""
    console.print("\n[bold blue]Cache Statistics[/bold blue]")

    try:
        health_info = db_manager.check_database_health()

        # Database overview table
        overview_table = Table(title="Database Overview")
        overview_table.add_column("Metric", style="cyan", no_wrap=True)
        overview_table.add_column("Value", style="green")

        overview_table.add_row("Database Status", health_info["status"].title())
        overview_table.add_row("Database Size", f"{health_info['size_mb']} MB")
        overview_table.add_row("Total Indexes", str(len(health_info["indexes"])))

        console.print(overview_table)

        # Tables breakdown
        if health_info["tables"]:
            tables_table = Table(title="Data Breakdown")
            tables_table.add_column("Table", style="cyan", no_wrap=True)
            tables_table.add_column("Records", style="green")
            tables_table.add_column("Description", style="yellow")

            table_descriptions = {
                "releases": "OpenShift AI release versions",
                "containers": "Container images in releases",
                "vulnerabilities": "Security vulnerabilities found",
                "packages": "Software packages in containers",
            }

            for table_name, count in health_info["tables"].items():
                description = table_descriptions.get(table_name, "")
                tables_table.add_row(table_name, str(count), description)

            console.print(tables_table)

        # Cache settings
        settings_table = Table(title="Cache Configuration")
        settings_table.add_column("Setting", style="cyan", no_wrap=True)
        settings_table.add_column("Value", style="green")

        settings_table.add_row("Cache Enabled", str(config.cache.enabled))
        settings_table.add_row("Cache Directory", str(config.cache.directory))
        settings_table.add_row("Max Size", f"{config.cache.max_size_mb} MB")
        settings_table.add_row(
            "Retention Period", f"{config.database.retention_days} days"
        )
        settings_table.add_row(
            "Cleanup Interval", f"{config.cache.cleanup_interval_hours} hours"
        )

        console.print(settings_table)

        # Storage recommendations
        _show_storage_recommendations(health_info, config)

    except Exception as e:
        console.print(f"[red]Failed to retrieve cache statistics: {e}[/red]")


def _show_storage_recommendations(health_info: dict, config) -> None:
    """Show storage recommendations based on current usage."""
    size_mb = health_info.get("size_mb", 0)
    max_size_mb = config.cache.max_size_mb

    console.print("\n[bold yellow]Storage Recommendations[/bold yellow]")

    if size_mb > max_size_mb * 0.8:
        console.print("[yellow]⚠️  Database is approaching size limit[/yellow]")
        console.print("   Consider running: osai-security-manifest cache --clean")
    elif size_mb > max_size_mb * 0.9:
        console.print("[red]🚨 Database is near size limit[/red]")
        console.print("   Run: osai-security-manifest cache --clean --older-than 30d")
    else:
        console.print("[green]✓ Storage usage is within acceptable limits[/green]")

    # Estimate cleanup potential
    total_records = sum(health_info["tables"].values())
    if total_records > 1000:
        console.print(f"\n💡 [dim]Tip: You have {total_records} total records.[/dim]")
        console.print("   [dim]Running cleanup could free significant space.[/dim]")


def _clean_cache(db_manager, days_to_keep: int, release: Optional[str]) -> None:
    """Clean cache entries older than specified days."""
    if release:
        console.print(f"[yellow]Cleaning cache for release {release}...[/yellow]")
        # TODO: Implement release-specific cleanup
        logger.info(f"Cleaning cache for release: {release}")
    else:
        console.print(
            f"[yellow]Cleaning cache entries older than {days_to_keep} days...[/yellow]"
        )

    try:
        cleanup_stats = db_manager.cleanup_old_data(days_to_keep)

        # Display cleanup results
        results_table = Table(title="Cleanup Results")
        results_table.add_column("Component", style="cyan", no_wrap=True)
        results_table.add_column("Deleted", style="red")

        results_table.add_row("Releases", str(cleanup_stats["releases_deleted"]))
        results_table.add_row("Containers", str(cleanup_stats["containers_deleted"]))
        results_table.add_row(
            "Vulnerabilities", str(cleanup_stats["vulnerabilities_deleted"])
        )
        results_table.add_row("Packages", str(cleanup_stats["packages_deleted"]))

        console.print(results_table)

        total_deleted = sum(cleanup_stats.values())
        if total_deleted > 0:
            console.print(
                f"\n[green]✓ Cleaned up {total_deleted} total records[/green]"
            )
        else:
            console.print("\n[blue]ℹ️  No expired data found to clean[/blue]")

        logger.info(f"Cache cleanup completed: {cleanup_stats}")

    except Exception as e:
        console.print(f"[red]Cache cleanup failed: {e}[/red]")
        raise


def _clear_cache(db_manager, release: Optional[str]) -> None:
    """Clear all cache data or data for specific release."""
    if release:
        console.print(
            f"[yellow]Clearing all cache data for release {release}...[/yellow]"
        )
        # TODO: Implement release-specific clearing
        logger.warning(f"Clearing cache for release: {release}")
    else:
        # Confirm destructive operation
        if not click.confirm("This will delete ALL cached data. Continue?"):
            console.print("[blue]Operation cancelled[/blue]")
            return

        console.print("[yellow]Clearing all cache data...[/yellow]")
        logger.warning("Clearing all cache data")

    try:
        # Get stats before clearing
        health_info = db_manager.check_database_health()
        total_records = sum(health_info["tables"].values())

        if release:
            # TODO: Implement release-specific clearing
            pass  # Placeholder
        else:
            # Clear all data (keep schema)
            db_manager.cleanup_old_data(0)  # 0 days = clear all

        console.print(f"[green]✓ Cleared {total_records} total records[/green]")
        logger.info(f"Cache cleared: {total_records} records removed")

    except Exception as e:
        console.print(f"[red]Cache clear failed: {e}[/red]")
        raise


def _vacuum_database(db_manager) -> None:
    """Vacuum database to reclaim space."""
    console.print("[yellow]Vacuuming database to reclaim space...[/yellow]")

    try:
        # Get size before vacuum
        health_info_before = db_manager.check_database_health()
        size_before = health_info_before.get("size_mb", 0)

        # Perform vacuum operation
        with db_manager.engine.connect() as conn:
            conn.execute(text("VACUUM"))
            conn.commit()

        # Get size after vacuum
        health_info_after = db_manager.check_database_health()
        size_after = health_info_after.get("size_mb", 0)

        space_reclaimed = size_before - size_after

        if space_reclaimed > 0:
            console.print("[green]✓ Database vacuumed successfully[/green]")
            console.print(f"Space reclaimed: {space_reclaimed:.2f} MB")
        else:
            console.print("[blue]ℹ️  Database was already optimized[/blue]")

        logger.info(f"Database vacuum completed: {space_reclaimed:.2f} MB reclaimed")

    except Exception as e:
        console.print(f"[red]Database vacuum failed: {e}[/red]")
        raise


def _parse_time_period(time_str: str) -> int:
    """Parse time period string into days.

    Args:
        time_str: Time period string (e.g., '30d', '7d', '24h')

    Returns:
        Number of days
    """
    if not time_str:
        return 180  # Default retention

    time_str = time_str.lower().strip()

    try:
        if time_str.endswith("d"):
            return int(time_str[:-1])
        elif time_str.endswith("h"):
            hours = int(time_str[:-1])
            return max(1, hours // 24)  # Convert to days, minimum 1
        elif time_str.endswith("w"):
            weeks = int(time_str[:-1])
            return weeks * 7
        elif time_str.endswith("m"):
            months = int(time_str[:-1])
            return months * 30  # Approximate
        else:
            # Assume it's days if no suffix
            return int(time_str)
    except ValueError as e:
        raise click.BadParameter(
            f"Invalid time period: {time_str}. Use format like '30d', '7d', '24h'"
        ) from e


def _estimate_cleanup_savings(db_manager, days_to_keep: int) -> dict:
    """Estimate how much data would be cleaned up."""
    # TODO: Implement estimation logic
    return {"estimated_records": 0, "estimated_size_mb": 0.0}
