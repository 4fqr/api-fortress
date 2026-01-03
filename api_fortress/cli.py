"""
Command-line interface for API Fortress.
Premium CLI with Click framework.
"""

import click
import asyncio
import sys
from typing import Optional, List
from pathlib import Path

from api_fortress.models import ScanConfig, AuthType
from api_fortress.scanner import FortressScanner
from api_fortress.reporting import ReportFormatter
from api_fortress.display import display


@click.group(invoke_without_command=True)
@click.pass_context
@click.version_option(version="1.0.0", prog_name="API Fortress")
def cli(ctx: click.Context) -> None:
    """
    🏰 API Fortress - Professional API Security Testing Suite
    
    Industry-leading security scanner for REST and GraphQL APIs.
    Based on OWASP API Security Top 10.
    """
    if ctx.invoked_subcommand is None:
        display.print_banner()
        click.echo(ctx.get_help())


@cli.command()
@click.argument("url")
@click.option(
    "--methods",
    default="GET,POST,PUT,DELETE,PATCH",
    help="Comma-separated HTTP methods to test",
)
@click.option(
    "--header",
    "-H",
    multiple=True,
    help="Custom headers (format: 'Key: Value')",
)
@click.option(
    "--auth-type",
    type=click.Choice(["bearer", "basic", "apikey", "none"], case_sensitive=False),
    default="none",
    help="Authentication type",
)
@click.option(
    "--token",
    "-t",
    help="Authentication token or credentials",
)
@click.option(
    "--timeout",
    default=30,
    type=int,
    help="Request timeout in seconds",
)
@click.option(
    "--max-concurrent",
    default=10,
    type=int,
    help="Maximum concurrent requests",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output file path for report",
)
@click.option(
    "--format",
    type=click.Choice(["json", "html", "markdown"], case_sensitive=False),
    default="json",
    help="Report output format",
)
@click.option(
    "--no-verify-ssl",
    is_flag=True,
    help="Disable SSL certificate verification",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose output",
)
@click.option(
    "--exclude",
    multiple=True,
    help="Paths to exclude from scanning",
)
def scan(
    url: str,
    methods: str,
    header: tuple,
    auth_type: str,
    token: Optional[str],
    timeout: int,
    max_concurrent: int,
    output: Optional[str],
    format: str,
    no_verify_ssl: bool,
    verbose: bool,
    exclude: tuple,
) -> None:
    """
    Scan an API endpoint for security vulnerabilities.
    
    Example:
        fortress scan https://api.example.com
        
        fortress scan https://api.example.com --auth-type bearer --token YOUR_TOKEN
        
        fortress scan https://api.example.com --header "Authorization: Bearer token" -o report.json
    """
    display.print_banner()
    display.print_section_header("Initializing Security Scan", "🔍")

    # Parse headers
    headers = {}
    for h in header:
        if ": " in h:
            key, value = h.split(": ", 1)
            headers[key] = value

    # Parse methods
    method_list = [m.strip().upper() for m in methods.split(",")]

    # Display target info
    display.print_target_info(url, method_list, auth_type if auth_type != "none" else None)

    try:
        # Create configuration
        from pydantic import HttpUrl

        config = ScanConfig(
            target_url=HttpUrl(url),
            methods=method_list,
            headers=headers,
            auth_type=AuthType(auth_type),
            auth_token=token,
            timeout=timeout,
            max_concurrent=max_concurrent,
            verify_ssl=not no_verify_ssl,
            exclude_paths=list(exclude),
        )

        # Run scan
        scanner = FortressScanner(config)
        result = asyncio.run(scanner.scan())

        # Display summary
        display.print_summary(
            total_requests=result.total_requests,
            vulnerabilities=result.get_severity_counts(),
            duration=result.duration or 0,
        )

        # Generate security recommendations
        from api_fortress.recommendations import SecurityRecommendations
        rec_engine = SecurityRecommendations()
        recommendations = rec_engine.generate_recommendations(result)
        
        # Display recommendations
        display.print_info("\n" + rec_engine.format_recommendations(recommendations))

        # Generate and save report
        if output:
            formatter = ReportFormatter(result)

            if format == "json":
                report_content = formatter.to_json()
            elif format == "html":
                report_content = formatter.to_html()
            else:  # markdown
                report_content = formatter.to_markdown()

            Path(output).write_text(report_content, encoding="utf-8")
            display.print_success(f"Report saved to: {output}")

        # Exit with appropriate code
        if result.get_severity_counts().get("critical", 0) > 0:
            sys.exit(2)
        elif result.get_severity_counts().get("high", 0) > 0:
            sys.exit(1)

    except Exception as e:
        display.print_error(f"Scan failed: {str(e)}")
        if verbose:
            import traceback
            click.echo(traceback.format_exc())
        sys.exit(3)


@cli.command()
def version() -> None:
    """Display version information."""
    display.print_banner()
    click.echo("\n[bold cyan]Version:[/bold cyan] 1.0.0")
    click.echo("[bold cyan]Python:[/bold cyan] 3.9+")
    click.echo("[bold cyan]Author:[/bold cyan] API Fortress Team")


@cli.command()
def examples() -> None:
    """Show usage examples."""
    display.print_banner()

    examples_text = """
[bold cyan]Usage Examples:[/bold cyan]

[bold]Basic Scan:[/bold]
  fortress scan https://api.example.com

[bold]Scan with Authentication:[/bold]
  fortress scan https://api.example.com --auth-type bearer --token YOUR_TOKEN

[bold]Custom Headers:[/bold]
  fortress scan https://api.example.com -H "Authorization: Bearer token" -H "X-API-Key: key"

[bold]Specific Methods:[/bold]
  fortress scan https://api.example.com --methods GET,POST,DELETE

[bold]Generate HTML Report:[/bold]
  fortress scan https://api.example.com --format html -o report.html

[bold]Exclude Paths:[/bold]
  fortress scan https://api.example.com --exclude /health --exclude /metrics

[bold]Full Example:[/bold]
  fortress scan https://api.example.com \\
    --auth-type bearer \\
    --token YOUR_TOKEN \\
    --methods GET,POST,PUT,DELETE \\
    --timeout 60 \\
    --max-concurrent 5 \\
    --format html \\
    -o security-report.html \\
    --verbose
"""
    from rich.console import Console
    console = Console()
    console.print(examples_text)


def main() -> None:
    """Main entry point."""
    try:
        cli()
    except KeyboardInterrupt:
        display.print_warning("\nScan interrupted by user")
        sys.exit(130)
    except Exception as e:
        display.print_error(f"Fatal error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
