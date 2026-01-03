"""
Security Misconfiguration scanner.
Tests for common security misconfigurations.
"""

from typing import List
import re

from api_fortress.scanners import BaseScanner
from api_fortress.models import Vulnerability, Severity, VulnerabilityType


class SecurityMisconfigScanner(BaseScanner):
    """Scanner for security misconfiguration vulnerabilities."""

    async def scan(self, url: str, method: str) -> List[Vulnerability]:
        """Test for security misconfigurations."""
        vulnerabilities = []

        # Test 1: Missing security headers
        if await self._test_security_headers(url, method):
            vuln = self.create_vulnerability(
                name="Missing Security Headers",
                vuln_type=VulnerabilityType.SECURITY_MISCONFIG,
                severity=Severity.MEDIUM,
                endpoint=url,
                method=method,
                description=(
                    "The API response is missing critical security headers that protect "
                    "against common attacks such as XSS, clickjacking, and MIME sniffing."
                ),
                evidence="Missing: X-Content-Type-Options, X-Frame-Options, Content-Security-Policy",
                remediation=[
                    "Add X-Content-Type-Options: nosniff header",
                    "Add X-Frame-Options: DENY or SAMEORIGIN header",
                    "Implement Content-Security-Policy header",
                    "Add Strict-Transport-Security for HTTPS",
                    "Include X-XSS-Protection header",
                ],
                cwe_id="CWE-16",
                cvss_score=5.3,
            )
            vulnerabilities.append(vuln)

        # Test 2: Verbose error messages
        if await self._test_verbose_errors(url, method):
            vuln = self.create_vulnerability(
                name="Verbose Error Messages",
                vuln_type=VulnerabilityType.SECURITY_MISCONFIG,
                severity=Severity.LOW,
                endpoint=url,
                method=method,
                description=(
                    "The API returns detailed error messages that expose internal "
                    "implementation details, stack traces, or system information."
                ),
                evidence="Stack traces and system paths exposed in error responses",
                remediation=[
                    "Implement generic error messages for users",
                    "Log detailed errors server-side only",
                    "Disable debug mode in production",
                    "Use custom error pages",
                ],
                cwe_id="CWE-209",
                cvss_score=3.7,
            )
            vulnerabilities.append(vuln)

        # Test 3: Insecure HTTP methods enabled
        if await self._test_insecure_methods(url):
            vuln = self.create_vulnerability(
                name="Insecure HTTP Methods Enabled",
                vuln_type=VulnerabilityType.SECURITY_MISCONFIG,
                severity=Severity.MEDIUM,
                endpoint=url,
                method="OPTIONS",
                description=(
                    "The API allows potentially dangerous HTTP methods like TRACE, "
                    "which can be exploited for cross-site tracing (XST) attacks."
                ),
                evidence="TRACE method enabled",
                remediation=[
                    "Disable TRACE and TRACK methods",
                    "Restrict allowed HTTP methods to only those needed",
                    "Configure web server to block dangerous methods",
                ],
                cwe_id="CWE-16",
                cvss_score=4.3,
            )
            vulnerabilities.append(vuln)

        # Test 4: CORS misconfiguration
        if await self._test_cors_misconfig(url, method):
            vuln = self.create_vulnerability(
                name="CORS Misconfiguration",
                vuln_type=VulnerabilityType.SECURITY_MISCONFIG,
                severity=Severity.HIGH,
                endpoint=url,
                method=method,
                description=(
                    "The API has overly permissive CORS configuration, allowing "
                    "requests from any origin, which can lead to unauthorized data access."
                ),
                evidence="Access-Control-Allow-Origin: * header present",
                remediation=[
                    "Restrict CORS to specific trusted origins",
                    "Avoid using wildcard (*) for Access-Control-Allow-Origin",
                    "Validate Origin header on the server",
                    "Use credentials carefully with CORS",
                ],
                cwe_id="CWE-942",
                cvss_score=7.4,
            )
            vulnerabilities.append(vuln)

        return vulnerabilities

    async def _test_security_headers(self, url: str, method: str) -> bool:
        """Check for missing security headers."""
        response = await self.client.request(method, url)

        required_headers = [
            "x-content-type-options",
            "x-frame-options",
            "content-security-policy",
        ]

        missing_headers = [
            header for header in required_headers
            if header not in [h.lower() for h in response.headers.keys()]
        ]

        return len(missing_headers) >= 2

    async def _test_verbose_errors(self, url: str, method: str) -> bool:
        """Test for verbose error messages."""
        # Trigger an error with invalid input
        test_url = f"{url}/nonexistent-resource-12345"
        response = await self.client.request(method, test_url)

        error_indicators = [
            "stack trace",
            "exception",
            "line ",
            "file ",
            "traceback",
            "at com.",
            "at java.",
            "/var/www",
            "c:\\",
        ]

        body_lower = response.body.lower()
        return any(indicator in body_lower for indicator in error_indicators)

    async def _test_insecure_methods(self, url: str) -> bool:
        """Test for enabled insecure HTTP methods."""
        response = await self.client.options(url)

        if "allow" in [h.lower() for h in response.headers.keys()]:
            allowed = response.headers.get("Allow", "").upper()
            dangerous_methods = ["TRACE", "TRACK", "CONNECT"]
            return any(method in allowed for method in dangerous_methods)

        # Try TRACE directly
        trace_response = await self.client.request("TRACE", url)
        return 200 <= trace_response.status_code < 300

    async def _test_cors_misconfig(self, url: str, method: str) -> bool:
        """Test for CORS misconfiguration."""
        response = await self.client.request(
            method, url, headers={"Origin": "https://evil.com"}
        )

        acao = response.headers.get("Access-Control-Allow-Origin", "")
        return acao == "*" or acao == "https://evil.com"
