"""
Server-Side Request Forgery (SSRF) scanner.
Tests for SSRF vulnerabilities in API endpoints.
"""

from typing import List
import re

from api_fortress.scanners import BaseScanner
from api_fortress.models import Vulnerability, Severity, VulnerabilityType


class SSRFScanner(BaseScanner):
    """Scanner for SSRF vulnerabilities."""

    # Common SSRF payloads
    SSRF_PAYLOADS = [
        "http://localhost",
        "http://127.0.0.1",
        "http://0.0.0.0",
        "http://169.254.169.254",  # AWS metadata
        "http://metadata.google.internal",  # GCP metadata
        "http://[::1]",  # IPv6 localhost
        "http://127.0.0.1:8080",
        "http://localhost:3000",
        "file:///etc/passwd",
        "gopher://localhost",
    ]

    async def scan(self, url: str, method: str) -> List[Vulnerability]:
        """Test for SSRF vulnerabilities."""
        vulnerabilities = []

        if await self._test_ssrf(url, method):
            vuln = self.create_vulnerability(
                name="Server-Side Request Forgery (SSRF)",
                vuln_type=VulnerabilityType.SSRF,
                severity=Severity.CRITICAL,
                endpoint=url,
                method=method,
                description=(
                    "The API endpoint is vulnerable to Server-Side Request Forgery (SSRF). "
                    "An attacker can make the server perform requests to arbitrary locations, "
                    "potentially accessing internal resources, cloud metadata, or internal services."
                ),
                evidence="Successfully triggered server-side requests to internal resources",
                remediation=[
                    "Implement whitelist of allowed domains/IPs",
                    "Validate and sanitize all URL inputs",
                    "Block requests to private IP ranges and metadata endpoints",
                    "Use network segmentation to isolate sensitive services",
                    "Disable unnecessary URL schemes (file://, gopher://, etc.)",
                    "Implement proper egress filtering",
                ],
                cwe_id="CWE-918",
                cvss_score=9.1,
            )
            vulnerabilities.append(vuln)

        return vulnerabilities

    async def _test_ssrf(self, url: str, method: str) -> bool:
        """Test for SSRF vulnerabilities."""
        # Look for URL parameters in the endpoint
        url_params = ["url", "uri", "link", "src", "source", "target", "dest", "redirect"]

        for param in url_params:
            for payload in self.SSRF_PAYLOADS:
                # Test as query parameter
                test_url = f"{url}?{param}={payload}"
                response = await self.client.request(method, test_url)

                if self._is_ssrf_successful(response.body, response.status_code):
                    return True

                # Test in JSON body for POST/PUT/PATCH
                if method in ["POST", "PUT", "PATCH"]:
                    response = await self.client.request(
                        method, url, json={param: payload}
                    )
                    if self._is_ssrf_successful(response.body, response.status_code):
                        return True

        return False

    def _is_ssrf_successful(self, body: str, status_code: int) -> bool:
        """Check if SSRF was successful based on response."""
        # Check for metadata service responses
        metadata_indicators = [
            "ami-id",
            "instance-id",
            "iam/security-credentials",
            "computeMetadata",
            "project-id",
        ]

        # Check for local file access
        file_indicators = [
            "root:x:",
            "/bin/bash",
            "/bin/sh",
        ]

        # Check for internal service responses
        if 200 <= status_code < 300:
            body_lower = body.lower()
            if any(indicator in body_lower for indicator in metadata_indicators):
                return True
            if any(indicator in body for indicator in file_indicators):
                return True

        return False
