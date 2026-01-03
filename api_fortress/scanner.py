"""
Main security scanner engine.
Orchestrates all vulnerability scanners.
"""

import asyncio
from typing import List, Optional
import time
import uuid

from api_fortress.models import ScanResult, ScanConfig, Vulnerability
from api_fortress.http_client import FortressHTTPClient
from api_fortress.scanners.bola_scanner import BOLAScanner
from api_fortress.scanners.auth_scanner import AuthScanner
from api_fortress.scanners.injection_scanner import InjectionScanner
from api_fortress.scanners.misconfig_scanner import SecurityMisconfigScanner
from api_fortress.scanners.ssrf_scanner import SSRFScanner
from api_fortress.scanners.deep_analysis_scanner import DeepAnalysisScanner
from api_fortress.display import display


class FortressScanner:
    """Main security scanner orchestrator."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.client: Optional[FortressHTTPClient] = None
        self.scan_result: Optional[ScanResult] = None

    async def scan(self, endpoints: Optional[List[str]] = None) -> ScanResult:
        """Execute comprehensive security scan."""
        scan_id = str(uuid.uuid4())
        start_time = time.time()

        # Initialize scan result
        self.scan_result = ScanResult(
            scan_id=scan_id,
            target=str(self.config.target_url),
            config=self.config,
        )

        # Create HTTP client
        async with FortressHTTPClient(self.config) as client:
            self.client = client

            # Initialize scanners
            scanners = [
                BOLAScanner(client),
                AuthScanner(client),
                InjectionScanner(client),
                SecurityMisconfigScanner(client),
                SSRFScanner(client),
                DeepAnalysisScanner(client),  # Advanced deep scanning
            ]

            # Determine endpoints to test
            test_endpoints = endpoints or [str(self.config.target_url)]

            # Create progress bar
            with display.create_progress() as progress:
                total_tests = len(test_endpoints) * len(self.config.methods) * len(scanners)
                task = progress.add_task(
                    "[cyan]Scanning endpoints...", total=total_tests
                )

                # Scan each endpoint
                for endpoint in test_endpoints:
                    if any(exclude in endpoint for exclude in self.config.exclude_paths):
                        continue

                    for method in self.config.methods:
                        # Run all scanners on this endpoint
                        for scanner in scanners:
                            try:
                                vulnerabilities = await scanner.scan(endpoint, method)
                                self.scan_result.vulnerabilities.extend(vulnerabilities)

                                # Display vulnerabilities as they're found
                                for vuln in vulnerabilities:
                                    display.print_vulnerability(
                                        name=vuln.name,
                                        severity=vuln.severity,
                                        endpoint=vuln.endpoint,
                                        description=vuln.description,
                                        evidence=vuln.evidence,
                                    )
                            except Exception as e:
                                display.print_warning(
                                    f"Scanner error on {endpoint} [{method}]: {str(e)}"
                                )

                            progress.advance(task)

                        self.scan_result.endpoints_tested += 1

            # Finalize scan result
            self.scan_result.total_requests = client.get_request_count()
            self.scan_result.duration = time.time() - start_time
            self.scan_result.end_time = self.scan_result.start_time

        return self.scan_result

    def get_result(self) -> Optional[ScanResult]:
        """Get scan results."""
        return self.scan_result


async def quick_scan(url: str, **kwargs) -> ScanResult:
    """Quick scan utility function."""
    from pydantic import HttpUrl

    config = ScanConfig(
        target_url=HttpUrl(url),
        **kwargs
    )

    scanner = FortressScanner(config)
    return await scanner.scan()
