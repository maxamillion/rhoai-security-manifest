"""Compare command for analyzing differences between releases."""

from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from ...utils.logging import get_logger

console = Console()
logger = get_logger("cli.compare")


@click.command()
@click.option(
    "--from",
    "from_release",
    required=True,
    help="Source release version to compare from",
)
@click.option(
    "--to", "to_release", required=True, help="Target release version to compare to"
)
@click.option(
    "--format",
    type=click.Choice(["json", "csv", "html", "markdown", "table"]),
    default="table",
    help="Output format for the comparison report",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file path (default: console output for table format)",
)
@click.option(
    "--show-resolved", is_flag=True, help="Include vulnerabilities that were resolved"
)
@click.option("--show-new", is_flag=True, help="Include new vulnerabilities found")
@click.option(
    "--show-common",
    is_flag=True,
    help="Include vulnerabilities common to both releases",
)
@click.option(
    "--containers", multiple=True, help="Filter comparison to specific container names"
)
@click.pass_context
def compare(
    ctx: click.Context,
    from_release: str,
    to_release: str,
    format: str,
    output: Optional[Path],
    show_resolved: bool,
    show_new: bool,
    show_common: bool,
    containers: tuple,
):
    """Compare security posture between two OpenShift AI releases.

    This command analyzes the differences in vulnerability counts, security grades,
    and specific CVEs between two releases. It helps track security improvements
    or regressions over time.

    Examples:

        # Compare releases with table output
        osai-security-manifest compare --from 2.7.0 --to 2.8.0

        # Show only new vulnerabilities
        osai-security-manifest compare --from 2.7.0 --to 2.8.0 --show-new

        # Generate detailed HTML comparison report
        osai-security-manifest compare --from 2.7.0 --to 2.8.0 --format html -o comparison.html

        # Compare specific containers only
        osai-security-manifest compare --from 2.7.0 --to 2.8.0 --containers workbench
    """
    config = ctx.obj["config"]
    db_manager = ctx.obj["db_manager"]

    logger.info(f"Comparing releases {from_release} → {to_release}")

    # Set defaults for what to show if no flags specified
    if not any([show_resolved, show_new, show_common]):
        show_resolved = True
        show_new = True

    try:
        # Load release data
        from_data = _load_release_data(from_release, list(containers), db_manager)
        to_data = _load_release_data(to_release, list(containers), db_manager)

        if not from_data:
            console.print(f"[red]No data found for release {from_release}[/red]")
            console.print("Run 'generate' command first to collect data")
            raise click.Abort()

        if not to_data:
            console.print(f"[red]No data found for release {to_release}[/red]")
            console.print("Run 'generate' command first to collect data")
            raise click.Abort()

        # Perform comparison analysis
        comparison_data = _perform_comparison(
            from_data,
            to_data,
            from_release,
            to_release,
            show_resolved,
            show_new,
            show_common,
        )

        # Output results
        if format == "table" and output is None:
            _display_comparison_table(comparison_data)
        else:
            if output is None:
                output = _generate_comparison_filename(
                    from_release, to_release, format, config.reports.output_directory
                )

            output.parent.mkdir(parents=True, exist_ok=True)
            _write_comparison_report(comparison_data, output, format)

            if not config.quiet:
                console.print("\n[green]✓[/green] Comparison report generated")
                console.print(f"Report saved to: [cyan]{output}[/cyan]")

        logger.info(f"Comparison completed: {from_release} → {to_release}")

    except Exception as e:
        logger.error(f"Comparison failed: {e}")
        console.print(f"[red]Error: {e}[/red]")
        raise click.Abort() from e


def _load_release_data(
    release: str, filter_containers: list, db_manager
) -> Optional[dict]:
    """Load release data from database."""
    # TODO: Implement actual database loading
    logger.debug(f"Loading data for release {release}")

    # Mock data for now
    if release in ["2.7.0", "2.8.0"]:
        return {
            "release": release,
            "containers": [
                {
                    "name": "workbench",
                    "security_grade": "B" if release == "2.8.0" else "C",
                    "vulnerabilities": {
                        "critical": 0 if release == "2.8.0" else 1,
                        "high": 2,
                        "medium": 5 if release == "2.8.0" else 8,
                        "low": 12,
                    },
                    "cve_list": [
                        "CVE-2023-1001",
                        "CVE-2023-1002",
                        "CVE-2023-1003" if release == "2.7.0" else None,
                        "CVE-2023-1004" if release == "2.8.0" else None,
                    ],
                },
                {
                    "name": "notebook",
                    "security_grade": "A" if release == "2.8.0" else "B",
                    "vulnerabilities": {
                        "critical": 0,
                        "high": 1 if release == "2.8.0" else 3,
                        "medium": 3,
                        "low": 8,
                    },
                    "cve_list": [
                        "CVE-2023-2001",
                        "CVE-2023-2002" if release == "2.7.0" else None,
                        "CVE-2023-2003" if release == "2.8.0" else None,
                    ],
                },
            ],
        }

    return None


def _perform_comparison(
    from_data: dict,
    to_data: dict,
    from_release: str,
    to_release: str,
    show_resolved: bool,
    show_new: bool,
    show_common: bool,
) -> dict:
    """Perform detailed comparison between releases."""
    logger.debug("Performing release comparison analysis")

    comparison = {
        "from_release": from_release,
        "to_release": to_release,
        "summary": {
            "containers_compared": 0,
            "grade_improvements": 0,
            "grade_degradations": 0,
            "new_vulnerabilities": 0,
            "resolved_vulnerabilities": 0,
            "net_vulnerability_change": 0,
        },
        "containers": [],
        "filters": {
            "show_resolved": show_resolved,
            "show_new": show_new,
            "show_common": show_common,
        },
    }

    # Create lookup dictionaries
    from_containers = {c["name"]: c for c in from_data["containers"]}
    to_containers = {c["name"]: c for c in to_data["containers"]}

    # Find common containers
    common_containers = set(from_containers.keys()) & set(to_containers.keys())
    comparison["summary"]["containers_compared"] = len(common_containers)

    for container_name in common_containers:
        from_container = from_containers[container_name]
        to_container = to_containers[container_name]

        container_comparison = _compare_containers(from_container, to_container)
        comparison["containers"].append(container_comparison)

        # Update summary statistics
        if container_comparison["grade_change"] == "improved":
            comparison["summary"]["grade_improvements"] += 1
        elif container_comparison["grade_change"] == "degraded":
            comparison["summary"]["grade_degradations"] += 1

        comparison["summary"]["new_vulnerabilities"] += len(
            container_comparison["new_cves"]
        )
        comparison["summary"]["resolved_vulnerabilities"] += len(
            container_comparison["resolved_cves"]
        )

    # Calculate net change
    comparison["summary"]["net_vulnerability_change"] = (
        comparison["summary"]["new_vulnerabilities"]
        - comparison["summary"]["resolved_vulnerabilities"]
    )

    return comparison


def _compare_containers(from_container: dict, to_container: dict) -> dict:
    """Compare two container versions."""
    from_grade = from_container["security_grade"]
    to_grade = to_container["security_grade"]

    # Determine grade change
    grade_order = {"A": 5, "B": 4, "C": 3, "D": 2, "F": 1}
    from_score = grade_order.get(from_grade, 0)
    to_score = grade_order.get(to_grade, 0)

    if to_score > from_score:
        grade_change = "improved"
    elif to_score < from_score:
        grade_change = "degraded"
    else:
        grade_change = "unchanged"

    # Compare CVE lists
    from_cves = set(filter(None, from_container.get("cve_list", [])))
    to_cves = set(filter(None, to_container.get("cve_list", [])))

    new_cves = list(to_cves - from_cves)
    resolved_cves = list(from_cves - to_cves)
    common_cves = list(from_cves & to_cves)

    # Calculate vulnerability changes
    from_vuln = from_container["vulnerabilities"]
    to_vuln = to_container["vulnerabilities"]

    vuln_changes = {}
    for severity in ["critical", "high", "medium", "low"]:
        from_count = from_vuln.get(severity, 0)
        to_count = to_vuln.get(severity, 0)
        vuln_changes[severity] = to_count - from_count

    return {
        "name": from_container["name"],
        "from_grade": from_grade,
        "to_grade": to_grade,
        "grade_change": grade_change,
        "vulnerability_changes": vuln_changes,
        "new_cves": new_cves,
        "resolved_cves": resolved_cves,
        "common_cves": common_cves,
        "total_new": len(new_cves),
        "total_resolved": len(resolved_cves),
        "net_change": len(new_cves) - len(resolved_cves),
    }


def _display_comparison_table(comparison_data: dict) -> None:
    """Display comparison results in console table format."""
    # Summary table
    console.print(
        f"\n[bold blue]Release Comparison: {comparison_data['from_release']} → {comparison_data['to_release']}[/bold blue]\n"
    )

    summary_table = Table(title="Summary")
    summary_table.add_column("Metric", style="cyan", no_wrap=True)
    summary_table.add_column("Value", style="green")

    summary = comparison_data["summary"]
    summary_table.add_row("Containers Compared", str(summary["containers_compared"]))
    summary_table.add_row("Grade Improvements", str(summary["grade_improvements"]))
    summary_table.add_row("Grade Degradations", str(summary["grade_degradations"]))
    summary_table.add_row("New Vulnerabilities", str(summary["new_vulnerabilities"]))
    summary_table.add_row(
        "Resolved Vulnerabilities", str(summary["resolved_vulnerabilities"])
    )
    summary_table.add_row("Net Change", str(summary["net_vulnerability_change"]))

    console.print(summary_table)

    # Container details table
    if comparison_data["containers"]:
        console.print("\n")
        details_table = Table(title="Container Comparison Details")
        details_table.add_column("Container", style="cyan", no_wrap=True)
        details_table.add_column("Grade Change", style="yellow")
        details_table.add_column("New CVEs", style="red")
        details_table.add_column("Resolved CVEs", style="green")
        details_table.add_column("Net Change", style="blue")

        for container in comparison_data["containers"]:
            grade_display = f"{container['from_grade']} → {container['to_grade']}"
            if container["grade_change"] == "improved":
                grade_display = f"[green]{grade_display} ↑[/green]"
            elif container["grade_change"] == "degraded":
                grade_display = f"[red]{grade_display} ↓[/red]"

            net_change = container["net_change"]
            net_display = str(net_change)
            if net_change > 0:
                net_display = f"[red]+{net_change}[/red]"
            elif net_change < 0:
                net_display = f"[green]{net_change}[/green]"

            details_table.add_row(
                container["name"],
                grade_display,
                str(container["total_new"]),
                str(container["total_resolved"]),
                net_display,
            )

        console.print(details_table)


def _generate_comparison_filename(
    from_release: str, to_release: str, format: str, output_dir: Path
) -> Path:
    """Generate comparison report filename."""
    from datetime import datetime

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"rhoai_comparison_{from_release}_to_{to_release}_{timestamp}.{format}"

    return output_dir / filename


def _write_comparison_report(
    comparison_data: dict, output_path: Path, format: str
) -> None:
    """Write comparison report to file."""
    logger.info(f"Writing {format.upper()} comparison report to {output_path}")

    if format == "json":
        _write_json_comparison(comparison_data, output_path)
    elif format == "csv":
        _write_csv_comparison(comparison_data, output_path)
    elif format == "html":
        _write_html_comparison(comparison_data, output_path)
    elif format == "markdown":
        _write_markdown_comparison(comparison_data, output_path)
    else:
        raise ValueError(f"Unsupported format: {format}")


def _write_json_comparison(comparison_data: dict, output_path: Path) -> None:
    """Write JSON comparison report."""
    import json

    with open(output_path, "w") as f:
        json.dump(comparison_data, f, indent=2)


def _write_csv_comparison(comparison_data: dict, output_path: Path) -> None:
    """Write CSV comparison report."""
    import csv

    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)

        # Header
        writer.writerow(
            [
                "Container",
                "From Grade",
                "To Grade",
                "Grade Change",
                "New CVEs",
                "Resolved CVEs",
                "Net Change",
            ]
        )

        # Data rows
        for container in comparison_data["containers"]:
            writer.writerow(
                [
                    container["name"],
                    container["from_grade"],
                    container["to_grade"],
                    container["grade_change"],
                    container["total_new"],
                    container["total_resolved"],
                    container["net_change"],
                ]
            )


def _write_html_comparison(comparison_data: dict, output_path: Path) -> None:
    """Write HTML comparison report."""
    # TODO: Implement proper HTML template
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Release Comparison: {comparison_data['from_release']} → {comparison_data['to_release']}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            .header {{ border-bottom: 2px solid #ccc; padding-bottom: 20px; }}
            .summary {{ margin: 20px 0; background: #f5f5f5; padding: 15px; }}
            .container {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; }}
            .improved {{ background-color: #d4edda; }}
            .degraded {{ background-color: #f8d7da; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Release Comparison Report</h1>
            <h2>{comparison_data['from_release']} → {comparison_data['to_release']}</h2>
        </div>

        <div class="summary">
            <h2>Summary</h2>
            <p>Containers Compared: {comparison_data['summary']['containers_compared']}</p>
            <p>Grade Improvements: {comparison_data['summary']['grade_improvements']}</p>
            <p>Grade Degradations: {comparison_data['summary']['grade_degradations']}</p>
            <p>New Vulnerabilities: {comparison_data['summary']['new_vulnerabilities']}</p>
            <p>Resolved Vulnerabilities: {comparison_data['summary']['resolved_vulnerabilities']}</p>
        </div>

        <div class="containers">
            <h2>Container Details</h2>
            {''.join(f'<div class="container {c["grade_change"]}"><h3>{c["name"]}</h3><p>Grade: {c["from_grade"]} → {c["to_grade"]}</p><p>New CVEs: {c["total_new"]}, Resolved: {c["total_resolved"]}</p></div>' for c in comparison_data["containers"])}
        </div>
    </body>
    </html>
    """

    with open(output_path, "w") as f:
        f.write(html_content)


def _write_markdown_comparison(comparison_data: dict, output_path: Path) -> None:
    """Write Markdown comparison report."""
    md_content = f"""# Release Comparison Report

## {comparison_data['from_release']} → {comparison_data['to_release']}

### Summary

- **Containers Compared:** {comparison_data['summary']['containers_compared']}
- **Grade Improvements:** {comparison_data['summary']['grade_improvements']}
- **Grade Degradations:** {comparison_data['summary']['grade_degradations']}
- **New Vulnerabilities:** {comparison_data['summary']['new_vulnerabilities']}
- **Resolved Vulnerabilities:** {comparison_data['summary']['resolved_vulnerabilities']}
- **Net Change:** {comparison_data['summary']['net_vulnerability_change']}

### Container Details

| Container | Grade Change | New CVEs | Resolved CVEs | Net Change |
|-----------|--------------|----------|---------------|------------|
"""

    for container in comparison_data["containers"]:
        grade_change = f"{container['from_grade']} → {container['to_grade']}"
        md_content += f"| {container['name']} | {grade_change} | {container['total_new']} | {container['total_resolved']} | {container['net_change']} |\n"

    with open(output_path, "w") as f:
        f.write(md_content)
