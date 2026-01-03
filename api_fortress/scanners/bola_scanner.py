"""
Broken Object Level Authorization (BOLA) scanner.
Tests for unauthorized access to objects.
"""

from typing import List
import re
import json

from api_fortress.scanners import BaseScanner
from api_fortress.models import Vulnerability, Severity, VulnerabilityType


class BOLAScanner(BaseScanner):
    """Scanner for Broken Object Level Authorization vulnerabilities."""

    async def scan(self, url: str, method: str) -> List[Vulnerability]:
        """Test for BOLA vulnerabilities."""
        vulnerabilities = []

        # Test 1: ID parameter manipulation
        if await self._test_id_manipulation(url, method):
            vuln = self.create_vulnerability(
                name="Broken Object Level Authorization (BOLA) Detected",
                vuln_type=VulnerabilityType.BOLA,
                severity=Severity.HIGH,
                endpoint=url,
                method=method,
                description=(
                    "OWASP API1:2023 - The API endpoint allows access to objects by manipulating ID parameters "
                    "without proper authorization checks. This vulnerability occurs when an API doesn't verify "
                    "that the authenticated user has permission to access the requested object. An attacker could "
                    "access, modify, or delete objects belonging to other users by simply changing ID values.\n\n"
                    "Example: Changing /api/users/123 to /api/users/456 grants access to another user's data.\n\n"
                    "Impact: Unauthorized data access, privacy violations, potential data modification or deletion."
                ),
                evidence=f"Successfully accessed resources with modified ID parameters. Response returned 200 OK for manipulated IDs.",
                remediation=[
                    "Implement proper authorization checks for ALL object accesses",
                    "Validate that the authenticated user owns or has permission for the requested object",
                    "Use UUIDs or non-sequential identifiers instead of predictable sequential IDs",
                    "Implement a policy enforcement layer that checks permissions before data access",
                    "Log and monitor all object access attempts for anomaly detection",
                    "Never rely solely on client-side checks or user input for authorization",
                ],
                cwe_id="CWE-639",
                cvss_score=8.2,
            )
            vulnerabilities.append(vuln)

        # Test 2: Missing authorization header
        if await self._test_missing_auth(url, method):
            vuln = self.create_vulnerability(
                name="Missing Authentication - Unauthenticated Access",
                vuln_type=VulnerabilityType.BOLA,
                severity=Severity.CRITICAL,
                endpoint=url,
                method=method,
                description=(
                    "OWASP API2:2023 - The API endpoint responds successfully without authentication headers, "
                    "allowing completely unauthorized access to potentially sensitive resources. This is a critical "
                    "security flaw where the API doesn't require users to prove their identity before accessing data.\n\n"
                    "This was detected on an endpoint that appears to handle sensitive operations based on its path "
                    "(contains /api/, /admin/, /user, /account, /profile, or similar patterns).\n\n"
                    "Impact: Complete unauthorized access, data breaches, privacy violations, potential for mass data extraction."
                ),
                evidence=f"Endpoint returned {method} 200 OK without any authentication headers. No 401 or 403 status returned.",
                remediation=[
                    "Require authentication for ALL sensitive endpoints (JWT, OAuth2, API Keys, etc.)",
                    "Implement consistent authentication middleware across all routes",
                    "Return 401 Unauthorized for requests without valid authentication",
                    "Use allowlists for public endpoints, deny by default for everything else",
                    "Implement API gateway with centralized authentication enforcement",
                    "Add automated tests to verify authentication is required",
                ],
                cwe_id="CWE-306",
                cvss_score=9.1,
            )
            vulnerabilities.append(vuln)

        return vulnerabilities

    async def _test_id_manipulation(self, url: str, method: str) -> bool:
        """Test if ID parameters can be manipulated."""
        # Extract numeric IDs from URL
        id_patterns = re.findall(r'/(\d+)(?:/|$)', url)

        if not id_patterns:
            return False

        # Test with modified IDs
        test_ids = ["1", "999999", "0", "-1"]
        original_response = await self.client.request(method, url)

        for test_id in test_ids:
            modified_url = re.sub(r'/\d+(?=/|$)', f'/{test_id}', url, count=1)
            if modified_url != url:
                response = await self.client.request(method, modified_url)
                if 200 <= response.status_code < 300:
                    return True

        return False

    async def _test_missing_auth(self, url: str, method: str) -> bool:
        """Test if endpoint is accessible without authentication."""
        # Skip if this is a public endpoint (RSS, sitemap, robots.txt, etc.)
        public_patterns = ['/rss', '/feed', '/sitemap', '/robots.txt', '/favicon.ico', '.xml']
        if any(pattern in url.lower() for pattern in public_patterns):
            return False
        
        # Make request without auth headers
        response = await self.client.request(method, url, headers={"Authorization": ""})
        
        # Only flag if this looks like it should require auth (e.g., /api/, /admin/, user data)
        sensitive_patterns = ['/api/', '/admin/', '/user', '/account', '/profile', '/dashboard']
        is_sensitive = any(pattern in url.lower() for pattern in sensitive_patterns)
        
        return (200 <= response.status_code < 300) and is_sensitive
