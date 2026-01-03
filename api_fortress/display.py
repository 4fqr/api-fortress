"""
Premium display utilities for API Fortress.
Provides beautiful, professional terminal UI components.
"""

from typing import Optional, List, Dict, Any
from rich.console import Console
from rich.theme import Theme
from rich.panel import Panel
from rich.table import Table
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeRemainingColumn,
)
from rich.layout import Layout
from rich.text import Text
from rich.box import ROUNDED, HEAVY, DOUBLE
from rich.style import Style
import time

# Define premium color scheme
THEME = Theme(
    {
        "primary": "bold bright_cyan",
        "secondary": "bold bright_magenta",
        "success": "bold bright_green",
        "warning": "bold bright_yellow",
        "error": "bold bright_red",
        "info": "bright_blue",
        "critical": "bold white on red",
        "high": "bold bright_red",
        "medium": "bold bright_yellow",
        "low": "bold bright_blue",
        "accent": "bold bright_white",
        "muted": "dim white",
        "border": "bright_cyan",
    }
)

console = Console(theme=THEME)


class FortressDisplay:
    """Premium display manager for API Fortress."""

    def __init__(self) -> None:
        self.console = console
        self.start_time = time.time()

    def print_banner(self) -> None:
        """Display the API Fortress banner."""
        banner = """
[bold bright_cyan]
   █████╗ ██████╗ ██╗    ███████╗ ██████╗ ██████╗ ████████╗██████╗ ███████╗███████╗███████╗
  ██╔══██╗██╔══██╗██║    ██╔════╝██╔═══██╗██╔══██╗╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔════╝
  ███████║██████╔╝██║    █████╗  ██║   ██║██████╔╝   ██║   ██████╔╝█████╗  ███████╗███████╗
  ██╔══██║██╔═══╝ ██║    ██╔══╝  ██║   ██║██╔══██╗   ██║   ██╔══██╗██╔══╝  ╚════██║╚════██║
  ██║  ██║██║     ██║    ██║     ╚██████╔╝██║  ██║   ██║   ██║  ██║███████╗███████║███████║
  ╚═╝  ╚═╝╚═╝     ╚═╝    ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
[/bold bright_cyan]
[bold bright_magenta]                  Professional API Security Testing Suite[/bold bright_magenta]
[muted]                          v1.0.0 | OWASP API Top 10[/muted]
"""
        self.console.print(banner)
        self.console.print()

    def print_section_header(self, title: str, icon: str = "🔍") -> None:
        """Print a styled section header."""
        self.console.print()
        self.console.print(
            Panel(
                f"[accent]{icon}  {title}[/accent]",
                border_style="border",
                box=ROUNDED,
                padding=(0, 2),
            )
        )
        self.console.print()

    def print_target_info(self, target: str, methods: List[str], auth_type: Optional[str]) -> None:
        """Display target information."""
        table = Table(show_header=False, box=ROUNDED, border_style="border", padding=(0, 1))
        table.add_column("Key", style="primary")
        table.add_column("Value", style="accent")

        table.add_row("Target URL", target)
        table.add_row("HTTP Methods", ", ".join(methods))
        table.add_row("Authentication", auth_type or "None")
        table.add_row("Scan Started", time.strftime("%Y-%m-%d %H:%M:%S"))

        self.console.print(table)
        self.console.print()

    def create_progress(self) -> Progress:
        """Create a premium progress bar."""
        return Progress(
            SpinnerColumn(spinner_name="dots12", style="primary"),
            TextColumn("[progress.description]{task.description}", style="accent"),
            BarColumn(
                complete_style="success",
                finished_style="success",
                pulse_style="primary",
            ),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            console=self.console,
        )

    def print_vulnerability(
        self,
        name: str,
        severity: str,
        endpoint: str,
        description: str,
        evidence: Optional[str] = None,
    ) -> None:
        """Display a vulnerability finding."""
        severity_styles = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
        }

        style = severity_styles.get(severity.upper(), "info")

        content = f"[{style}]● {severity}[/{style}] - [accent]{name}[/accent]\n"
        content += f"[muted]Endpoint:[/muted] [info]{endpoint}[/info]\n"
        content += f"[muted]Description:[/muted] {description}"

        if evidence:
            content += f"\n[muted]Evidence:[/muted] [dim]{evidence[:200]}...[/dim]"

        self.console.print(
            Panel(
                content,
                border_style=style,
                box=HEAVY,
                padding=(1, 2),
            )
        )

    def print_summary(
        self,
        total_requests: int,
        vulnerabilities: Dict[str, int],
        duration: float,
    ) -> None:
        """Display scan summary."""
        self.print_section_header("Scan Summary", "📊")

        # Create summary table
        table = Table(
            show_header=True,
            box=DOUBLE,
            border_style="border",
            header_style="primary",
            padding=(0, 2),
        )
        table.add_column("Metric", style="accent")
        table.add_column("Value", justify="right", style="success")

        table.add_row("Total Requests", str(total_requests))
        table.add_row("Duration", f"{duration:.2f}s")
        table.add_row("Critical", f"[critical]{vulnerabilities.get('critical', 0)}[/critical]")
        table.add_row("High", f"[high]{vulnerabilities.get('high', 0)}[/high]")
        table.add_row("Medium", f"[medium]{vulnerabilities.get('medium', 0)}[/medium]")
        table.add_row("Low", f"[low]{vulnerabilities.get('low', 0)}[/low]")
        table.add_row(
            "Total Vulnerabilities",
            f"[accent]{sum(vulnerabilities.values())}[/accent]",
        )

        self.console.print(table)

    def print_success(self, message: str) -> None:
        """Print success message."""
        self.console.print(f"[success]✓[/success] {message}")

    def print_info(self, message: str) -> None:
        """Print info message."""
        self.console.print(f"[info]ℹ[/info] {message}")

    def print_warning(self, message: str) -> None:
        """Print warning message."""
        self.console.print(f"[warning]⚠[/warning] {message}")

    def print_error(self, message: str) -> None:
        """Print error message."""
        self.console.print(f"[error]✗[/error] {message}")

    def print_mitigation(self, title: str, steps: List[str]) -> None:
        """Display mitigation recommendations."""
        content = f"[accent]{title}[/accent]\n\n"
        for i, step in enumerate(steps, 1):
            content += f"[primary]{i}.[/primary] {step}\n"

        self.console.print(
            Panel(
                content.strip(),
                title="[success]🛡️  Mitigation Strategies[/success]",
                border_style="success",
                box=ROUNDED,
                padding=(1, 2),
            )
        )


# Global display instance
display = FortressDisplay()
