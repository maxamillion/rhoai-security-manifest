"""Container validation utilities for RHOAI security manifest tool."""

import asyncio
from pathlib import Path
from typing import Any, Optional

import httpx
import yaml
from rich.console import Console
from rich.table import Table

from ..utils.logging import get_logger

logger = get_logger("utils.container_validation")
console = Console()


class ContainerValidator:
    """Validates container configurations and availability."""

    def __init__(self, timeout: int = 30):
        """Initialize the validator.

        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self._client = httpx.AsyncClient(timeout=timeout)

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self._client.aclose()

    async def close(self):
        """Close the HTTP client."""
        await self._client.aclose()

    async def validate_container_config(
        self, config_path: Optional[Path] = None
    ) -> dict[str, Any]:
        """Validate container configuration file.

        Args:
            config_path: Path to containers.yaml file

        Returns:
            Validation results with statistics and findings
        """
        if config_path is None:
            config_path = Path("config/containers.yaml")

        if not config_path.exists():
            return {
                "success": False,
                "error": f"Configuration file not found: {config_path}",
                "statistics": {},
                "issues": [],
            }

        try:
            with open(config_path) as f:
                config = yaml.safe_load(f)
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to parse YAML: {e}",
                "statistics": {},
                "issues": [],
            }

        return await self._validate_config_structure(config, config_path)

    async def _validate_config_structure(
        self, config: dict[str, Any], config_path: Path
    ) -> dict[str, Any]:
        """Validate the structure and content of the configuration."""
        issues = []
        statistics = {}

        if "rhoai_containers" not in config:
            issues.append("Missing 'rhoai_containers' section in configuration")
            return {
                "success": False,
                "error": "Invalid configuration structure",
                "statistics": statistics,
                "issues": issues,
            }

        rhoai_containers = config["rhoai_containers"]
        total_releases = len(rhoai_containers)
        total_containers = 0
        seen_containers = set()
        duplicate_containers = set()

        statistics["total_releases"] = total_releases
        statistics["releases"] = {}

        for release, containers in rhoai_containers.items():
            if not isinstance(containers, list):
                issues.append(f"Release {release}: containers must be a list")
                continue

            release_stats = {
                "container_count": len(containers),
                "unique_containers": 0,
                "duplicates": 0,
                "missing_fields": 0,
            }

            release_containers = set()

            for i, container in enumerate(containers):
                if not isinstance(container, dict):
                    issues.append(
                        f"Release {release}: container {i} must be a dictionary"
                    )
                    continue

                # Check required fields
                required_fields = ["namespace", "repository"]
                missing = [field for field in required_fields if field not in container]
                if missing:
                    issues.append(
                        f"Release {release}: container {i} missing fields: {missing}"
                    )
                    release_stats["missing_fields"] += 1
                    continue

                # Check for duplicates within release
                container_key = f"{container.get('namespace', '')}/{container.get('repository', '')}"
                if container_key in release_containers:
                    issues.append(
                        f"Release {release}: duplicate container {container_key}"
                    )
                    release_stats["duplicates"] += 1
                    duplicate_containers.add(container_key)
                else:
                    release_containers.add(container_key)
                    release_stats["unique_containers"] += 1

                # Check for duplicates across releases
                if container_key in seen_containers:
                    issues.append(
                        f"Container {container_key} appears in multiple releases"
                    )

                seen_containers.add(container_key)
                total_containers += 1

            statistics["releases"][release] = release_stats

        statistics["total_containers"] = total_containers
        statistics["unique_containers"] = len(seen_containers)
        statistics["duplicate_containers"] = len(duplicate_containers)

        return {
            "success": len(issues) == 0,
            "statistics": statistics,
            "issues": issues,
            "config_path": str(config_path),
        }

    async def check_container_accessibility(
        self, containers: list[dict[str, str]], max_concurrent: int = 5
    ) -> dict[str, Any]:
        """Check if containers are accessible in the registry.

        Args:
            containers: List of container specifications
            max_concurrent: Maximum concurrent requests

        Returns:
            Accessibility check results
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        results = {
            "total_checked": len(containers),
            "accessible": 0,
            "inaccessible": 0,
            "errors": 0,
            "details": [],
        }

        async def check_single_container(container: dict[str, str]) -> dict[str, Any]:
            async with semaphore:
                namespace = container.get("namespace", "")
                repository = container.get("repository", "")
                registry = container.get("registry", "registry.redhat.io")

                container_url = (
                    f"https://{registry}/v2/{namespace}/{repository}/manifests/latest"
                )

                try:
                    response = await self._client.head(container_url)
                    accessible = response.status_code in [
                        200,
                        401,
                        403,
                    ]  # 401/403 means exists but requires auth

                    return {
                        "container": f"{namespace}/{repository}",
                        "registry": registry,
                        "accessible": accessible,
                        "status_code": response.status_code,
                        "error": None,
                    }
                except Exception as e:
                    return {
                        "container": f"{namespace}/{repository}",
                        "registry": registry,
                        "accessible": False,
                        "status_code": None,
                        "error": str(e),
                    }

        # Execute all checks concurrently
        tasks = [check_single_container(container) for container in containers]
        check_results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in check_results:
            if isinstance(result, Exception):
                results["errors"] += 1
                results["details"].append(
                    {"container": "unknown", "accessible": False, "error": str(result)}
                )
            else:
                results["details"].append(result)
                if result["accessible"]:
                    results["accessible"] += 1
                else:
                    results["inaccessible"] += 1

        return results

    def print_validation_report(self, validation_result: dict[str, Any]) -> None:
        """Print a formatted validation report."""
        console.print(
            "\n🔍 [bold blue]Container Configuration Validation Report[/bold blue]\n"
        )

        if not validation_result["success"]:
            console.print("❌ [red]Validation Failed[/red]")
            if "error" in validation_result:
                console.print(f"   Error: {validation_result['error']}")

            if validation_result.get("issues"):
                console.print("\n📋 [yellow]Issues Found:[/yellow]")
                for issue in validation_result["issues"]:
                    console.print(f"   • {issue}")
            return

        console.print("✅ [green]Configuration is valid[/green]")

        # Statistics table
        stats = validation_result["statistics"]
        table = Table(title="Configuration Statistics")
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Value", style="green")

        table.add_row("Total Releases", str(stats.get("total_releases", 0)))
        table.add_row("Total Containers", str(stats.get("total_containers", 0)))
        table.add_row("Unique Containers", str(stats.get("unique_containers", 0)))

        if stats.get("duplicate_containers", 0) > 0:
            table.add_row(
                "Duplicates", str(stats["duplicate_containers"]), style="yellow"
            )

        console.print(table)

        # Per-release breakdown
        if "releases" in stats:
            console.print("\n📊 [bold]Per-Release Breakdown:[/bold]")
            release_table = Table()
            release_table.add_column("Release", style="cyan")
            release_table.add_column("Containers", style="green")
            release_table.add_column("Unique", style="blue")
            release_table.add_column("Issues", style="red")

            for release, release_stats in stats["releases"].items():
                issues = release_stats.get("duplicates", 0) + release_stats.get(
                    "missing_fields", 0
                )
                release_table.add_row(
                    release,
                    str(release_stats.get("container_count", 0)),
                    str(release_stats.get("unique_containers", 0)),
                    str(issues) if issues > 0 else "None",
                )

            console.print(release_table)

        if validation_result.get("issues"):
            console.print("\n⚠️ [yellow]Issues Found:[/yellow]")
            for issue in validation_result["issues"]:
                console.print(f"   • {issue}")

    def print_accessibility_report(self, accessibility_result: dict[str, Any]) -> None:
        """Print a formatted accessibility report."""
        console.print("\n🌐 [bold blue]Container Accessibility Report[/bold blue]\n")

        stats = accessibility_result
        table = Table(title="Accessibility Summary")
        table.add_column("Status", style="cyan", no_wrap=True)
        table.add_column("Count", style="green")
        table.add_column("Percentage", style="blue")

        total = stats["total_checked"]
        if total > 0:
            table.add_row("Total Checked", str(total), "100%")
            table.add_row(
                "Accessible",
                str(stats["accessible"]),
                f"{(stats['accessible'] / total * 100):.1f}%",
            )
            table.add_row(
                "Inaccessible",
                str(stats["inaccessible"]),
                f"{(stats['inaccessible'] / total * 100):.1f}%",
            )
            if stats["errors"] > 0:
                table.add_row(
                    "Errors",
                    str(stats["errors"]),
                    f"{(stats['errors'] / total * 100):.1f}%",
                    style="red",
                )

        console.print(table)

        # Show inaccessible containers
        inaccessible = [d for d in stats["details"] if not d["accessible"]]
        if inaccessible:
            console.print(
                f"\n❌ [red]Inaccessible Containers ({len(inaccessible)}):[/red]"
            )
            for detail in inaccessible[:10]:  # Show first 10
                error_info = f" ({detail['error']})" if detail.get("error") else ""
                console.print(
                    f"   • {detail['container']} - Status: {detail.get('status_code', 'Error')}{error_info}"
                )

            if len(inaccessible) > 10:
                console.print(f"   ... and {len(inaccessible) - 10} more")


async def validate_rhoai_containers(
    config_path: Optional[Path] = None,
    check_accessibility: bool = False,
    release_filter: Optional[str] = None,
) -> dict[str, Any]:
    """Main validation function for RHOAI containers.

    Args:
        config_path: Path to containers.yaml file
        check_accessibility: Whether to check container accessibility
        release_filter: Only validate specific release

    Returns:
        Complete validation results
    """
    async with ContainerValidator() as validator:
        # Validate configuration structure
        config_result = await validator.validate_container_config(config_path)

        if not config_result["success"]:
            return {
                "config_validation": config_result,
                "accessibility_check": None,
            }

        # Check accessibility if requested
        accessibility_result = None
        if check_accessibility:
            if config_path is None:
                config_path = Path("config/containers.yaml")

            with open(config_path) as f:
                config = yaml.safe_load(f)

            containers_to_check = []
            for release, containers in config.get("rhoai_containers", {}).items():
                if release_filter and release != release_filter:
                    continue
                containers_to_check.extend(containers)

            if containers_to_check:
                accessibility_result = await validator.check_container_accessibility(
                    containers_to_check
                )

        return {
            "config_validation": config_result,
            "accessibility_check": accessibility_result,
        }
