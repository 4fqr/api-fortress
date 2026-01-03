"""
Authentication security scanner.
Tests for broken authentication mechanisms.
"""

from typing import List
import json

from api_fortress.scanners import BaseScanner
from api_fortress.models import Vulnerability, Severity, VulnerabilityType


class AuthScanner(BaseScanner):
    """Scanner for authentication vulnerabilities."""

    async def scan(self, url: str, method: str) -> List[Vulnerability]:
        """Test for authentication vulnerabilities."""
        vulnerabilities = []

        # Test 1: Weak token validation
        if await self._test_weak_token(url, method):
            vuln = self.create_vulnerability(
                name="Weak Token Validation",
                vuln_type=VulnerabilityType.BROKEN_AUTH,
                severity=Severity.HIGH,
                endpoint=url,
                method=method,
                description=(
                    "The API accepts invalid or malformed authentication tokens, "
                    "indicating weak token validation mechanisms."
                ),
                evidence="Invalid tokens accepted by the endpoint",
                remediation=[
                    "Implement strong token validation (signature verification)",
                    "Use industry-standard token formats (JWT with proper signing)",
                    "Validate token expiration and claims",
                    "Implement token revocation mechanisms",
                ],
                cwe_id="CWE-287",
                cvss_score=8.1,
            )
            vulnerabilities.append(vuln)

        # Test 2: Credential stuffing vulnerability
        if await self._test_rate_limiting(url, method):
            vuln = self.create_vulnerability(
                name="Missing Rate Limiting on Authentication",
                vuln_type=VulnerabilityType.BROKEN_AUTH,
                severity=Severity.MEDIUM,
                endpoint=url,
                method=method,
                description=(
                    "The authentication endpoint lacks rate limiting, making it vulnerable "
                    "to brute force and credential stuffing attacks."
                ),
                evidence="Multiple rapid authentication attempts allowed",
                remediation=[
                    "Implement rate limiting on authentication endpoints",
                    "Use CAPTCHA after failed attempts",
                    "Implement account lockout after multiple failures",
                    "Monitor and alert on suspicious authentication patterns",
                ],
                cwe_id="CWE-307",
                cvss_score=6.5,
            )
            vulnerabilities.append(vuln)

        # Test 3: Insecure session management
        if await self._test_session_security(url, method):
            vuln = self.create_vulnerability(
                name="Insecure Session Management",
                vuln_type=VulnerabilityType.BROKEN_AUTH,
                severity=Severity.HIGH,
                endpoint=url,
                method=method,
                description=(
                    "Session tokens lack security attributes such as HttpOnly, Secure, "
                    "or SameSite flags, making them vulnerable to theft."
                ),
                evidence="Session cookies missing security flags",
                remediation=[
                    "Set HttpOnly flag on session cookies",
                    "Set Secure flag to ensure HTTPS-only transmission",
                    "Implement SameSite attribute to prevent CSRF",
                    "Use short session timeouts",
                    "Regenerate session IDs after authentication",
                ],
                cwe_id="CWE-614",
                cvss_score=7.4,
            )
            vulnerabilities.append(vuln)

        return vulnerabilities

    async def _test_weak_token(self, url: str, method: str) -> bool:
        """Test if weak or invalid tokens are accepted."""
        # Skip public endpoints that don't require authentication
        public_patterns = ['/rss', '/feed', '/sitemap', '/robots.txt', '.xml', '/public']
        if any(pattern in url.lower() for pattern in public_patterns):
            return False
        
        # First check if endpoint requires auth at all
        baseline = await self.client.request(method, url)
        if baseline.status_code == 401 or baseline.status_code == 403:
            # Good! Endpoint requires auth. Now test weak tokens.
            weak_tokens = ["invalid", "12345", "Bearer invalid", "null", "undefined"]
            for token in weak_tokens:
                response = await self.client.request(
                    method, url, headers={"Authorization": f"Bearer {token}"}
                )
                # If invalid token works but no token didn't, that's a problem
                if 200 <= response.status_code < 300:
                    return True
        
        return False

    async def _test_rate_limiting(self, url: str, method: str) -> bool:
        """Test if rate limiting is implemented."""
        # Skip for public content endpoints
        public_patterns = ['/rss', '/feed', '/sitemap', '/robots.txt', '.xml', '/public']
        if any(pattern in url.lower() for pattern in public_patterns):
            return False
        
        # Only test rate limiting on sensitive endpoints
        auth_patterns = ['/login', '/auth', '/token', '/api/', '/admin/']
        if not any(pattern in url.lower() for pattern in auth_patterns):
            return False
        
        # Make rapid requests
        responses = []
        for _ in range(10):
            response = await self.client.request(method, url)
            responses.append(response)

        # Check if any rate limiting occurred
        rate_limited = any(r.status_code == 429 for r in responses)
        return not rate_limited

    async def _test_session_security(self, url: str, method: str) -> bool:
        """Test session cookie security."""
        response = await self.client.request(method, url)

        if "Set-Cookie" in response.headers:
            cookie = response.headers["Set-Cookie"].lower()
            # Check for security flags
            has_httponly = "httponly" in cookie
            has_secure = "secure" in cookie
            has_samesite = "samesite" in cookie

            return not (has_httponly and has_secure and has_samesite)

        return False
