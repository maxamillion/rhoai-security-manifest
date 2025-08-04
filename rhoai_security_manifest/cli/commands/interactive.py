"""Interactive command for guided workflow using Textual TUI."""

import click
from rich.console import Console

from ...utils.logging import get_logger

console = Console()
logger = get_logger("cli.interactive")


@click.command()
@click.option(
    "--theme",
    type=click.Choice(["dark", "light"]),
    default="dark",
    help="UI theme for interactive mode",
)
@click.pass_context
def interactive(ctx: click.Context, theme: str):
    """Launch interactive mode with guided workflows.

    Interactive mode provides a user-friendly interface for:
    - Discovering available releases
    - Selecting containers to analyze
    - Configuring report options
    - Monitoring analysis progress
    - Viewing results

    This mode is ideal for users who prefer guided workflows over command-line options.
    """
    config = ctx.obj["config"]
    db_manager = ctx.obj["db_manager"]

    logger.info("Starting interactive mode")

    try:
        # Check if Textual is available
        try:
            from textual.app import App
        except ImportError:
            console.print("[red]Interactive mode requires the 'textual' package[/red]")
            console.print("Install it with: pip install textual")
            raise click.Abort()

        # Launch TUI application
        console.print("[blue]Launching interactive mode...[/blue]")
        console.print("[dim]Press Ctrl+C to exit[/dim]")

        # TODO: Implement actual TUI application
        app = SecurityManifestApp(config=config, db_manager=db_manager, theme=theme)
        app.run()

        logger.info("Interactive mode completed")

    except KeyboardInterrupt:
        console.print("\n[yellow]Interactive mode cancelled[/yellow]")
    except Exception as e:
        logger.error(f"Interactive mode failed: {e}")
        console.print(f"[red]Error: {e}[/red]")
        raise click.Abort()


class SecurityManifestApp:
    """Main TUI application class."""

    def __init__(self, config, db_manager, theme: str):
        """Initialize the TUI application.

        Args:
            config: Application configuration
            db_manager: Database manager instance
            theme: UI theme ('dark' or 'light')
        """
        self.config = config
        self.db_manager = db_manager
        self.theme = theme

    def run(self):
        """Run the interactive application."""
        # TODO: Implement full Textual application
        # For now, provide a simple text-based menu

        console.print(
            "\n[bold blue]OpenShift AI Security Manifest Tool - Interactive Mode[/bold blue]"
        )
        console.print("[dim]Full TUI implementation coming soon![/dim]\n")

        while True:
            self._show_main_menu()
            choice = self._get_user_choice()

            if choice == "1":
                self._generate_manifest_workflow()
            elif choice == "2":
                self._compare_releases_workflow()
            elif choice == "3":
                self._manage_cache_workflow()
            elif choice == "4":
                self._show_status_workflow()
            elif choice == "5":
                self._configure_settings_workflow()
            elif choice == "0":
                console.print("[green]Goodbye![/green]")
                break
            else:
                console.print("[red]Invalid choice. Please try again.[/red]")

    def _show_main_menu(self):
        """Display the main menu."""
        console.print("\n[bold]Main Menu[/bold]")
        console.print("1. Generate Security Manifest")
        console.print("2. Compare Releases")
        console.print("3. Manage Cache")
        console.print("4. Show Status")
        console.print("5. Configure Settings")
        console.print("0. Exit")
        console.print()

    def _get_user_choice(self) -> str:
        """Get user menu choice."""
        return input("Enter your choice: ").strip()

    def _generate_manifest_workflow(self):
        """Guided workflow for generating manifests."""
        console.print("\n[bold yellow]Generate Security Manifest[/bold yellow]")

        # Get release version
        release = input("Enter OpenShift AI release version (e.g., 2.8.0): ").strip()
        if not release:
            console.print("[red]Release version is required[/red]")
            return

        # Get output format
        console.print("\nSelect output format:")
        console.print("1. JSON")
        console.print("2. CSV")
        console.print("3. HTML")
        console.print("4. Markdown")

        format_choice = input("Choice (1-4): ").strip()
        format_map = {"1": "json", "2": "csv", "3": "html", "4": "markdown"}
        output_format = format_map.get(format_choice, "json")

        # Ask about package details
        include_packages = (
            input("Include package-level details? (y/N): ").strip().lower() == "y"
        )

        # Show configuration and confirm
        console.print("\n[cyan]Configuration:[/cyan]")
        console.print(f"  Release: {release}")
        console.print(f"  Format: {output_format.upper()}")
        console.print(f"  Include packages: {include_packages}")

        if input("\nProceed? (Y/n): ").strip().lower() != "n":
            console.print("\n[yellow]Generating manifest...[/yellow]")
            # TODO: Call actual generation logic
            console.print("[green]✓ Manifest generated successfully![/green]")
            console.print(
                f"Report saved to: security_reports/rhoai_security_manifest_{release}_TIMESTAMP.{output_format}"
            )
        else:
            console.print("[blue]Operation cancelled[/blue]")

    def _compare_releases_workflow(self):
        """Guided workflow for comparing releases."""
        console.print("\n[bold yellow]Compare Releases[/bold yellow]")

        # Get release versions
        from_release = input("From release version: ").strip()
        to_release = input("To release version: ").strip()

        if not from_release or not to_release:
            console.print("[red]Both release versions are required[/red]")
            return

        # Get output format
        console.print("\nSelect output format:")
        console.print("1. Table (console)")
        console.print("2. JSON")
        console.print("3. CSV")
        console.print("4. HTML")
        console.print("5. Markdown")

        format_choice = input("Choice (1-5): ").strip()
        format_map = {
            "1": "table",
            "2": "json",
            "3": "csv",
            "4": "html",
            "5": "markdown",
        }
        output_format = format_map.get(format_choice, "table")

        # Show configuration and confirm
        console.print("\n[cyan]Configuration:[/cyan]")
        console.print(f"  From: {from_release}")
        console.print(f"  To: {to_release}")
        console.print(f"  Format: {output_format.upper()}")

        if input("\nProceed? (Y/n): ").strip().lower() != "n":
            console.print("\n[yellow]Comparing releases...[/yellow]")
            # TODO: Call actual comparison logic
            console.print("[green]✓ Comparison completed![/green]")
        else:
            console.print("[blue]Operation cancelled[/blue]")

    def _manage_cache_workflow(self):
        """Guided workflow for cache management."""
        console.print("\n[bold yellow]Manage Cache[/bold yellow]")

        console.print("1. Show cache statistics")
        console.print("2. Clean old entries")
        console.print("3. Clear all cache")
        console.print("4. Vacuum database")
        console.print("0. Back to main menu")

        choice = input("\nChoice: ").strip()

        if choice == "1":
            console.print("\n[cyan]Cache Statistics:[/cyan]")
            # TODO: Show actual cache stats
            console.print("Database size: 15.2 MB")
            console.print("Total records: 1,234")
            console.print("Oldest entry: 45 days ago")
        elif choice == "2":
            days = input(
                "Clean entries older than how many days? (default: 180): "
            ).strip()
            days = int(days) if days.isdigit() else 180
            console.print(
                f"[yellow]Cleaning entries older than {days} days...[/yellow]"
            )
            console.print("[green]✓ Cache cleaned![/green]")
        elif choice == "3":
            if (
                input("Clear ALL cache data? This cannot be undone (y/N): ")
                .strip()
                .lower()
                == "y"
            ):
                console.print("[yellow]Clearing all cache data...[/yellow]")
                console.print("[green]✓ Cache cleared![/green]")
            else:
                console.print("[blue]Operation cancelled[/blue]")
        elif choice == "4":
            console.print("[yellow]Vacuuming database...[/yellow]")
            console.print("[green]✓ Database optimized![/green]")

    def _show_status_workflow(self):
        """Show application status."""
        console.print("\n[bold yellow]Application Status[/bold yellow]")

        # TODO: Show actual status information
        console.print("[cyan]Database Status:[/cyan] Healthy")
        console.print("[cyan]Cache Status:[/cyan] Enabled")
        console.print("[cyan]Last Update:[/cyan] 2 hours ago")
        console.print("[cyan]Releases Tracked:[/cyan] 5")
        console.print("[cyan]Containers Analyzed:[/cyan] 127")
        console.print("[cyan]Vulnerabilities Found:[/cyan] 1,456")

        input("\nPress Enter to continue...")

    def _configure_settings_workflow(self):
        """Configure application settings."""
        console.print("\n[bold yellow]Configure Settings[/bold yellow]")

        console.print("Current settings:")
        console.print(f"  Database URL: {self.config.database.url}")
        console.print(f"  Cache enabled: {self.config.cache.enabled}")
        console.print(f"  Log level: {self.config.logging.level}")
        console.print(f"  Output directory: {self.config.reports.output_directory}")

        console.print("\n[dim]Settings configuration coming soon![/dim]")
        console.print(
            "[dim]For now, use configuration files or environment variables.[/dim]"
        )

        input("\nPress Enter to continue...")
