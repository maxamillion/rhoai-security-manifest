"""Generate command for creating security manifests."""

from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from ...utils.logging import get_logger

console = Console()
logger = get_logger("cli.generate")


@click.command()
@click.option(
    "--release", required=True, help="OpenShift AI release version (e.g., 2.8.0)"
)
@click.option(
    "--format",
    type=click.Choice(["json", "csv", "html", "markdown"]),
    default="json",
    help="Output format for the report",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file path (default: auto-generated)",
)
@click.option(
    "--packages", is_flag=True, help="Include package-level vulnerability details"
)
@click.option(
    "--offline", is_flag=True, help="Use cached data only, do not make API calls"
)
@click.option(
    "--force-refresh", is_flag=True, help="Ignore cache and refresh all data from APIs"
)
@click.option(
    "--containers",
    multiple=True,
    help="Filter to specific container names (can be used multiple times)",
)
@click.pass_context
def generate(
    ctx: click.Context,
    release: str,
    format: str,
    output: Optional[Path],
    packages: bool,
    offline: bool,
    force_refresh: bool,
    containers: list[str],
):
    """Generate security manifest for an OpenShift AI release.

    This command queries the Red Hat Container Catalog to discover all containers
    in the specified release, analyzes their security posture, and generates a
    comprehensive security report.

    Examples:

        # Generate JSON report for release 2.8.0
        osai-security-manifest generate --release 2.8.0

        # Generate HTML report with package details
        osai-security-manifest generate --release 2.8.0 --format html --packages

        # Generate report for specific containers only
        osai-security-manifest generate --release 2.8.0 --containers workbench --containers notebook

        # Use offline mode with cached data
        osai-security-manifest generate --release 2.8.0 --offline
    """
    config = ctx.obj["config"]
    ctx.obj["db_manager"]

    logger.info(f"Starting manifest generation for release {release}")

    if offline and force_refresh:
        console.print(
            "[red]Error: Cannot use --offline and --force-refresh together[/red]"
        )
        raise click.Abort()

    try:
        import asyncio

        from ...analysis.orchestrator import create_orchestrator

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            disable=config.quiet,
        ) as progress:

            # Step 1: Validate release and setup
            task = progress.add_task("Initializing...", total=None)
            _validate_release_format(release)

            # Determine output file if not specified
            if output is None:
                output = _generate_output_filename(
                    release, format, config.reports.output_directory
                )

            # Ensure output directory exists
            output.parent.mkdir(parents=True, exist_ok=True)

            progress.update(task, description="Setting up analysis orchestrator...")

            # Step 2: Create orchestrator and run analysis
            async def run_analysis():
                orchestrator = await create_orchestrator(config)

                try:
                    analysis_result = await orchestrator.analyze_release(
                        release_version=release,
                        force_refresh=force_refresh,
                        offline_mode=offline,
                        container_filter=list(containers) if containers else None,
                        include_packages=packages,
                    )
                    return analysis_result
                finally:
                    # Clean up API clients
                    await orchestrator.catalog_client.close()
                    await orchestrator.security_client.close()

            # Run the async analysis
            try:
                progress.update(task, description="Running security analysis...")
                analysis_result = asyncio.run(run_analysis())
            except Exception as e:
                logger.error(f"Analysis failed: {e}")
                console.print(f"\n[red]Analysis failed: {e}[/red]")

                # Provide helpful suggestions based on the error
                if "400 Bad Request" in str(e):
                    console.print(
                        "\n[yellow]The Red Hat Container Catalog API has changed.[/yellow]"
                    )
                    console.print(
                        "[yellow]This tool needs to be updated to work with the new API.[/yellow]"
                    )
                elif "No containers found" in str(e) or (
                    hasattr(e, "args") and "No containers found" in str(e.args)
                ):
                    console.print(
                        "\n[yellow]No containers were found for this release.[/yellow]"
                    )
                    console.print("[yellow]Possible reasons:[/yellow]")
                    console.print("  - The release version might not exist yet")
                    console.print(
                        "  - The release might use different naming conventions"
                    )
                    console.print(
                        "  - RHOAI containers might require authentication to access"
                    )
                    console.print(
                        "  - The manual configuration might be missing containers"
                    )
                    console.print(f"\n[dim]Searched for: RHOAI {release}[/dim]")
                    console.print("\n[yellow]Suggestions:[/yellow]")
                    console.print(
                        "  - Check the config/containers.yaml file for manual container definitions"
                    )
                    console.print(
                        "  - Ensure the release version is defined in the configuration"
                    )
                    console.print(
                        "  - Try using --offline mode if you have cached data"
                    )
                    console.print(
                        "  - Use --containers flag to filter specific container names"
                    )
                    console.print(
                        "\n[cyan]Manual configuration location:[/cyan] config/containers.yaml"
                    )
                    console.print(
                        "[cyan]To add containers:[/cyan] Edit the file and add container definitions under your release version"
                    )

                raise click.Abort() from None

            progress.update(task, description="Generating report...")

            # Step 3: Convert analysis result to report format
            report_data = _convert_analysis_to_report(analysis_result, packages, config)

            # Step 4: Write report to file
            _write_report(report_data, output, format)

            progress.update(task, description="Complete!")

        # Success message
        if not config.quiet:
            console.print("\n[green]✓[/green] Security manifest generated successfully")
            console.print(f"Report saved to: [cyan]{output}[/cyan]")
            console.print(f"Format: [yellow]{format.upper()}[/yellow]")

            # Show summary statistics
            _show_summary_stats(report_data)

        logger.info(f"Manifest generation completed: {output}")

    except Exception as e:
        logger.error(f"Manifest generation failed: {e}")
        console.print(f"[red]Error: {e}[/red]")
        raise click.Abort() from e


def _validate_release_format(release: str) -> None:
    """Validate release version format."""
    import re

    # Check for semantic version pattern (e.g., 2.8.0, 2.10.1)
    if not re.match(r"^\d+\.\d+\.\d+$", release):
        raise click.BadParameter(
            f"Invalid release format: {release}. Expected format: X.Y.Z (e.g., 2.8.0)"
        )


def _generate_output_filename(release: str, format: str, output_dir: Path) -> Path:
    """Generate output filename based on release and format."""
    from datetime import datetime

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"rhoai_security_manifest_{release}_{timestamp}.{format}"

    return output_dir / filename


def _convert_analysis_to_report(
    analysis_result, include_packages: bool, config
) -> dict:
    """Convert analysis result to report format."""

    return {
        "metadata": {
            "release": analysis_result.release_version,
            "generated_at": analysis_result.generated_at.isoformat(),
            "tool_version": analysis_result.metadata["tool_version"],
            "include_packages": include_packages,
            "total_containers": len(analysis_result.containers),
        },
        "summary": {
            "total_vulnerabilities": sum(
                c["total_vulnerabilities"] for c in analysis_result.containers
            ),
            "grade_distribution": analysis_result.summary["grade_distribution"],
            "average_vulnerabilities": (
                round(
                    sum(c["total_vulnerabilities"] for c in analysis_result.containers)
                    / len(analysis_result.containers),
                    1,
                )
                if analysis_result.containers
                else 0
            ),
            "security_posture": analysis_result.summary["security_posture"],
            "average_score": analysis_result.summary["average_score"],
        },
        "containers": analysis_result.containers,
    }


def _write_report(report_data: dict, output_path: Path, format: str) -> None:
    """Write report data to file in specified format."""
    logger.info(f"Writing {format.upper()} report to {output_path}")

    if format == "json":
        _write_json_report(report_data, output_path)
    elif format == "csv":
        _write_csv_report(report_data, output_path)
    elif format == "html":
        _write_html_report(report_data, output_path)
    elif format == "markdown":
        _write_markdown_report(report_data, output_path)
    else:
        raise ValueError(f"Unsupported format: {format}")


def _write_json_report(report_data: dict, output_path: Path) -> None:
    """Write JSON format report."""
    import json

    with open(output_path, "w") as f:
        json.dump(report_data, f, indent=2)


def _write_csv_report(report_data: dict, output_path: Path) -> None:
    """Write CSV format report."""
    import csv

    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)

        # Header
        writer.writerow(
            [
                "Container Name",
                "Registry URL",
                "Security Grade",
                "Critical",
                "High",
                "Medium",
                "Low",
                "Total Vulnerabilities",
            ]
        )

        # Data rows
        for container in report_data["containers"]:
            vuln = container["vulnerabilities"]
            writer.writerow(
                [
                    container["name"],
                    container["registry_url"],
                    container["security_grade"],
                    vuln["critical"],
                    vuln["high"],
                    vuln["medium"],
                    vuln["low"],
                    container["total_vulnerabilities"],
                ]
            )


def _write_html_report(report_data: dict, output_path: Path) -> None:
    """Write HTML format report."""
    from ...reports.generators.html import HTMLReportGenerator

    generator = HTMLReportGenerator()
    generator.generate_report(report_data, output_path)


def _write_markdown_report(report_data: dict, output_path: Path) -> None:
    """Write Markdown format report."""
    md_content = f"""# OpenShift AI Security Manifest

**Release:** {report_data['metadata']['release']}
**Generated:** {report_data['metadata']['generated_at']}

## Summary

- **Total Containers:** {report_data['metadata']['total_containers']}
- **Total Vulnerabilities:** {report_data['summary']['total_vulnerabilities']}
- **Average Vulnerabilities per Container:** {report_data['summary']['average_vulnerabilities']}

## Grade Distribution

"""

    for grade, count in report_data["summary"]["grade_distribution"].items():
        md_content += f"- **{grade}:** {count} containers\n"

    md_content += "\n## Container Analysis\n\n"

    for container in report_data["containers"]:
        vuln = container["vulnerabilities"]
        md_content += f"""### {container['name']}

- **Security Grade:** {container['security_grade']}
- **Registry:** {container['registry_url']}
- **Vulnerabilities:** Critical: {vuln['critical']}, High: {vuln['high']}, Medium: {vuln['medium']}, Low: {vuln['low']}
- **Total:** {container['total_vulnerabilities']}

"""

    with open(output_path, "w") as f:
        f.write(md_content)


def _show_summary_stats(report_data: dict) -> None:
    """Display summary statistics in the console."""
    from rich.table import Table

    # Grade distribution table
    table = Table(title="Security Grade Distribution")
    table.add_column("Grade", style="cyan", no_wrap=True)
    table.add_column("Containers", style="green")

    for grade, count in report_data["summary"]["grade_distribution"].items():
        table.add_row(grade, str(count))

    console.print(table)

    # Vulnerability summary
    console.print("\n📊 [bold]Summary Statistics[/bold]")
    console.print(f"   Total Containers: {report_data['metadata']['total_containers']}")
    console.print(
        f"   Total Vulnerabilities: {report_data['summary']['total_vulnerabilities']}"
    )
    console.print(
        f"   Average per Container: {report_data['summary']['average_vulnerabilities']}"
    )
