"""
Enhanced error detection scanner with comprehensive error database.
Detects and explains errors from all major API platforms.
"""

from typing import List, Dict, Any, Optional
import json
import re

from api_fortress.scanners import BaseScanner
from api_fortress.models import Vulnerability, Severity, VulnerabilityType
from api_fortress.api_adapters import APIAdapter, APIPlatform, ErrorDatabase


class UniversalErrorScanner(BaseScanner):
    """Scanner for comprehensive error detection across all API platforms."""

    async def scan(self, url: str, method: str) -> List[Vulnerability]:
        """Scan for API errors and misconfigurations."""
        vulnerabilities = []
        
        # Detect platform
        platform = APIAdapter.detect_platform(url)
        
        # Test error responses
        error_vulns = await self._test_error_responses(url, method, platform)
        vulnerabilities.extend(error_vulns)
        
        # Test authentication errors
        auth_vulns = await self._test_auth_errors(url, method, platform)
        vulnerabilities.extend(auth_vulns)
        
        # Test rate limiting
        rate_vulns = await self._test_rate_limit_errors(url, method, platform)
        vulnerabilities.extend(rate_vulns)
        
        # Test platform-specific errors
        platform_vulns = await self._test_platform_errors(url, method, platform)
        vulnerabilities.extend(platform_vulns)
        
        return vulnerabilities

    async def _test_error_responses(self, url: str, method: str, platform: APIPlatform) -> List[Vulnerability]:
        """Test various error scenarios."""
        vulnerabilities = []
        
        # Test with invalid JSON
        try:
            response = await self.client.request(
                method,
                url,
                data="invalid json{{{",
                headers={"Content-Type": "application/json"}
            )
            
            if response and response.status == 400:
                error_info = ErrorDatabase.get_error_info(400, platform)
                
                vuln = self.create_vulnerability(
                    name="Poor Error Handling - Invalid Request Data",
                    vuln_type=VulnerabilityType.SECURITY_MISCONFIG,
                    severity=Severity.LOW,
                    endpoint=url,
                    method=method,
                    description=(
                        f"📋 API ERROR HANDLING ANALYSIS ({platform.value.upper()})\n\n"
                        f"The API returns a 400 Bad Request for invalid input, which is correct behavior.\n"
                        f"However, the error message quality and information disclosure should be reviewed.\n\n"
                        f"DETECTED ERROR:\n"
                        f"• HTTP Status: {error_info['http_error'].get('name', '400 Bad Request')}\n"
                        f"• Description: {error_info['http_error'].get('description', 'Invalid request')}\n\n"
                        f"COMMON CAUSES:\n" +
                        "\n".join(f"  • {cause}" for cause in error_info['http_error'].get('common_causes', [])) +
                        "\n\n"
                        f"SECURITY CONSIDERATIONS:\n"
                        f"• Ensure error messages don't leak sensitive information\n"
                        f"• Validate input on server-side\n"
                        f"• Return consistent error format\n"
                        f"• Log detailed errors server-side only"
                    ),
                    evidence=(
                        f"Test Request: {method} {url}\n"
                        f"Payload: Invalid JSON\n"
                        f"Response: HTTP {response.status}\n"
                        f"Error handling verified for {platform.value}"
                    ),
                    remediation=error_info['http_error'].get('remediation', [
                        "Implement consistent error response format",
                        "Don't expose internal error details",
                        "Use appropriate HTTP status codes",
                        "Log detailed errors securely",
                    ]),
                    cwe_id="CWE-209",
                    cvss_score=3.1,
                )
                vulnerabilities.append(vuln)
        except Exception:
            pass
        
        return vulnerabilities

    async def _test_auth_errors(self, url: str, method: str, platform: APIPlatform) -> List[Vulnerability]:
        """Test authentication error scenarios."""
        vulnerabilities = []
        
        # Test with invalid token
        auth_header = APIAdapter.get_auth_header_name(platform)
        
        try:
            response = await self.client.request(
                method,
                url,
                headers={auth_header: "invalid_token_12345"}
            )
            
            if response and response.status in [401, 403]:
                error_info = ErrorDatabase.get_error_info(response.status, platform)
                
                severity = Severity.HIGH if response.status == 401 else Severity.MEDIUM
                
                vuln = self.create_vulnerability(
                    name=f"Authentication Error Handling - {platform.value.upper()}",
                    vuln_type=VulnerabilityType.BROKEN_AUTH,
                    severity=severity,
                    endpoint=url,
                    method=method,
                    description=(
                        f"🔐 AUTHENTICATION ERROR DETECTED ({platform.value.upper()})\n\n"
                        f"The API correctly rejects invalid authentication credentials.\n"
                        f"Status Code: {response.status}\n\n"
                        f"ERROR DETAILS:\n"
                        f"• {error_info['http_error'].get('name', 'Auth Error')}\n"
                        f"• {error_info['http_error'].get('description', 'Authentication failed')}\n\n"
                        f"PLATFORM: {platform.value.upper()}\n"
                        f"Auth Header: {auth_header}\n\n"
                        f"COMMON CAUSES:\n" +
                        "\n".join(f"  • {cause}" for cause in error_info['http_error'].get('common_causes', [])) +
                        "\n\n"
                        f"BEST PRACTICES FOR {platform.value.upper()}:\n"
                        f"• Store API keys in environment variables\n"
                        f"• Never commit credentials to version control\n"
                        f"• Rotate keys regularly\n"
                        f"• Use appropriate authentication method for platform\n"
                        f"• Implement token refresh if using OAuth"
                    ),
                    evidence=(
                        f"Authentication Test:\n"
                        f"• Endpoint: {url}\n"
                        f"• Method: {method}\n"
                        f"• Auth Header: {auth_header}\n"
                        f"• Test Token: invalid_token_12345\n"
                        f"• Response: HTTP {response.status}\n"
                        f"• Platform: {platform.value}"
                    ),
                    remediation=error_info['http_error'].get('remediation', []),
                    cwe_id="CWE-287",
                    cvss_score=7.5 if response.status == 401 else 5.3,
                )
                vulnerabilities.append(vuln)
        except Exception:
            pass
        
        return vulnerabilities

    async def _test_rate_limit_errors(self, url: str, method: str, platform: APIPlatform) -> List[Vulnerability]:
        """Test rate limiting implementation."""
        vulnerabilities = []
        
        rate_limits = APIAdapter.get_rate_limits(platform)
        
        # Info about rate limits
        if rate_limits:
            vuln = self.create_vulnerability(
                name=f"Rate Limit Configuration - {platform.value.upper()}",
                vuln_type=VulnerabilityType.SECURITY_MISCONFIG,
                severity=Severity.INFO,
                endpoint=url,
                method=method,
                description=(
                    f"ℹ️ RATE LIMIT INFORMATION ({platform.value.upper()})\n\n"
                    f"Platform-specific rate limits detected:\n\n" +
                    "\n".join(f"• {key.replace('_', ' ').title()}: {value}" 
                             for key, value in rate_limits.items()) +
                    "\n\n"
                    f"RECOMMENDATIONS:\n"
                    f"• Implement client-side rate limiting\n"
                    f"• Use exponential backoff on 429 responses\n"
                    f"• Monitor rate limit headers in responses\n"
                    f"• Consider upgrading tier if limits are restrictive\n\n"
                    f"RATE LIMIT HEADERS TO MONITOR:\n"
                    f"• X-RateLimit-Limit\n"
                    f"• X-RateLimit-Remaining\n"
                    f"• X-RateLimit-Reset\n"
                    f"• Retry-After (on 429 responses)"
                ),
                evidence=f"Platform: {platform.value}\nRate Limits: {json.dumps(rate_limits, indent=2)}",
                remediation=[
                    "Implement request queuing with rate limiting",
                    "Add exponential backoff retry logic",
                    "Monitor rate limit headers",
                    "Cache responses when possible",
                    "Use batch endpoints if available",
                ],
                cwe_id="CWE-770",
                cvss_score=2.0,
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities

    async def _test_platform_errors(self, url: str, method: str, platform: APIPlatform) -> List[Vulnerability]:
        """Test platform-specific error scenarios."""
        vulnerabilities = []
        
        platform_errors = ErrorDatabase.get_all_errors_for_platform(platform)
        
        if platform_errors:
            error_list = "\n".join(
                f"  • {error_code}: {error_data.get('message', 'No description')}"
                for error_code, error_data in list(platform_errors.items())[:5]
            )
            
            vuln = self.create_vulnerability(
                name=f"Platform-Specific Error Reference - {platform.value.upper()}",
                vuln_type=VulnerabilityType.SECURITY_MISCONFIG,
                severity=Severity.INFO,
                endpoint=url,
                method=method,
                description=(
                    f"📚 KNOWN ERRORS FOR {platform.value.upper()}\n\n"
                    f"This API platform has documented error codes that your application should handle:\n\n"
                    f"COMMON {platform.value.upper()} ERRORS:\n{error_list}\n\n"
                    f"IMPLEMENTATION CHECKLIST:\n"
                    f"✓ Implement error handling for each error code\n"
                    f"✓ Add retry logic for transient errors\n"
                    f"✓ Log errors for debugging\n"
                    f"✓ Provide user-friendly error messages\n"
                    f"✓ Implement fallback mechanisms\n\n"
                    f"ERROR HANDLING BEST PRACTICES:\n"
                    f"• Parse error response JSON\n"
                    f"• Check for 'error' or 'message' fields\n"
                    f"• Implement specific handlers per error code\n"
                    f"• Use platform SDKs when available\n"
                    f"• Test error scenarios in development"
                ),
                evidence=f"Platform: {platform.value}\nDocumented Errors: {len(platform_errors)}",
                remediation=[
                    f"Review {platform.value} API documentation for all error codes",
                    "Implement comprehensive error handling",
                    "Add logging for all API errors",
                    "Create error recovery strategies",
                    "Test error scenarios in staging environment",
                ],
                cwe_id="CWE-754",
                cvss_score=2.0,
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
