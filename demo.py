"""
Example usage and demonstration of API Fortress.
"""

import asyncio
from pydantic import HttpUrl

from api_fortress.models import ScanConfig, AuthType
from api_fortress.scanner import FortressScanner
from api_fortress.reporting import ReportFormatter
from api_fortress.display import display


async def demo_scan() -> None:
    """Demonstrate API Fortress capabilities."""
    
    # Display banner
    display.print_banner()
    display.print_section_header("Demo Mode - Testing Against Public API", "🎯")
    
    # Configure scan for a public test API
    config = ScanConfig(
        target_url=HttpUrl("https://jsonplaceholder.typicode.com"),
        methods=["GET", "POST", "PUT", "DELETE"],
        auth_type=AuthType.NONE,
        timeout=15,
        max_concurrent=5,
        verify_ssl=True,
    )
    
    display.print_target_info(
        str(config.target_url),
        config.methods,
        None
    )
    
    # Run scan
    scanner = FortressScanner(config)
    
    # Test specific endpoints
    endpoints = [
        "https://jsonplaceholder.typicode.com/posts",
        "https://jsonplaceholder.typicode.com/users",
        "https://jsonplaceholder.typicode.com/comments",
    ]
    
    result = await scanner.scan(endpoints)
    
    # Display summary
    display.print_summary(
        total_requests=result.total_requests,
        vulnerabilities=result.get_severity_counts(),
        duration=result.duration or 0,
    )
    
    # Generate sample report
    display.print_section_header("Generating Reports", "📄")
    
    formatter = ReportFormatter(result)
    
    # Save reports in multiple formats
    with open("demo-report.json", "w", encoding="utf-8") as f:
        f.write(formatter.to_json())
    display.print_success("JSON report saved: demo-report.json")
    
    with open("demo-report.html", "w", encoding="utf-8") as f:
        f.write(formatter.to_html())
    display.print_success("HTML report saved: demo-report.html")
    
    with open("demo-report.md", "w", encoding="utf-8") as f:
        f.write(formatter.to_markdown())
    display.print_success("Markdown report saved: demo-report.md")
    
    display.print_info("\n✨ Demo completed successfully!")


def main() -> None:
    """Run demo."""
    try:
        asyncio.run(demo_scan())
    except KeyboardInterrupt:
        display.print_warning("\nDemo interrupted")
    except Exception as e:
        display.print_error(f"Demo failed: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
