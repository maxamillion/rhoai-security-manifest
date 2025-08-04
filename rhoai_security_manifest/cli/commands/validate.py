"""Validate command for checking container configurations."""

import asyncio
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from ...utils.container_validation import validate_rhoai_containers, ContainerValidator
from ...utils.logging import get_logger

console = Console()
logger = get_logger("cli.validate")


@click.command()
@click.option(
    "--config",
    type=click.Path(exists=True, path_type=Path),
    help="Path to containers.yaml configuration file (default: config/containers.yaml)"
)
@click.option(
    "--check-accessibility", 
    is_flag=True, 
    help="Check if containers are accessible in the registry (slower)"
)
@click.option(
    "--release",
    help="Only validate containers for specific release version"
)
@click.option(
    "--quiet",
    is_flag=True,
    help="Only show summary, suppress detailed output"
)
@click.pass_context
def validate(
    ctx: click.Context,
    config: Optional[Path],
    check_accessibility: bool,
    release: Optional[str],
    quiet: bool,
):
    """Validate container configuration and accessibility.
    
    This command validates the containers.yaml configuration file and optionally
    checks if the specified containers are accessible in their registries.
    
    Examples:
    
        # Basic configuration validation
        osai-security-manifest validate
        
        # Check configuration and container accessibility
        osai-security-manifest validate --check-accessibility
        
        # Validate only containers for release 2.19.0
        osai-security-manifest validate --release 2.19.0
        
        # Use custom configuration file
        osai-security-manifest validate --config /path/to/containers.yaml
    """
    app_config = ctx.obj["config"]
    logger.info("Starting container configuration validation")

    if quiet:
        app_config.quiet = True

    try:
        # Run validation
        result = asyncio.run(
            validate_rhoai_containers(
                config_path=config,
                check_accessibility=check_accessibility,
                release_filter=release
            )
        )

        # Create validator for reporting
        validator = ContainerValidator()

        # Print configuration validation results
        if not quiet:
            validator.print_validation_report(result["config_validation"])

        # Print accessibility results if available
        if result["accessibility_check"] and not quiet:
            validator.print_accessibility_report(result["accessibility_check"])

        # Summary for quiet mode or success message
        config_valid = result["config_validation"]["success"]
        
        if quiet:
            stats = result["config_validation"]["statistics"]
            total_containers = stats.get("total_containers", 0)
            total_releases = stats.get("total_releases", 0)
            
            if config_valid:
                console.print(f"✅ Configuration valid: {total_containers} containers across {total_releases} releases")
            else:
                issues_count = len(result["config_validation"].get("issues", []))
                console.print(f"❌ Configuration invalid: {issues_count} issues found")
                
            if result["accessibility_check"]:
                acc_stats = result["accessibility_check"]
                accessible = acc_stats["accessible"]
                total = acc_stats["total_checked"]
                console.print(f"🌐 Accessibility: {accessible}/{total} containers accessible")
        else:
            if config_valid:
                console.print("\n✅ [green]Validation completed successfully[/green]")
            else:
                console.print("\n❌ [red]Validation completed with issues[/red]")

        # Exit with error code if validation failed
        if not config_valid:
            raise click.Abort()

        logger.info("Container validation completed successfully")

    except Exception as e:
        logger.error(f"Validation failed: {e}")
        console.print(f"[red]Error: {e}[/red]")
        raise click.Abort() from e