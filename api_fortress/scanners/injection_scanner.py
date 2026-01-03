"""
Injection vulnerability scanner.
Tests for SQL, NoSQL, Command, and other injection flaws.
"""

from typing import List
import re

from api_fortress.scanners import BaseScanner
from api_fortress.models import Vulnerability, Severity, VulnerabilityType


class InjectionScanner(BaseScanner):
    """Scanner for injection vulnerabilities."""

    # Common injection payloads
    SQL_PAYLOADS = [
        "' OR '1'='1",
        "'; DROP TABLE users--",
        "' UNION SELECT NULL--",
        "admin'--",
        "1' AND '1'='1",
    ]

    NOSQL_PAYLOADS = [
        '{"$gt":""}',
        '{"$ne":null}',
        '{"$regex":".*"}',
    ]

    COMMAND_PAYLOADS = [
        "; ls -la",
        "| whoami",
        "`id`",
        "$(cat /etc/passwd)",
    ]

    LDAP_PAYLOADS = [
        "*",
        "*)(&",
        "*)(uid=*",
    ]

    async def scan(self, url: str, method: str) -> List[Vulnerability]:
        """Test for injection vulnerabilities."""
        vulnerabilities = []

        # Test SQL Injection
        if await self._test_sql_injection(url, method):
            vuln = self.create_vulnerability(
                name="SQL Injection Vulnerability",
                vuln_type=VulnerabilityType.BOPLA,
                severity=Severity.CRITICAL,
                endpoint=url,
                method=method,
                description=(
                    "The endpoint is vulnerable to SQL injection attacks. Malicious SQL "
                    "payloads can be injected through user inputs, potentially allowing "
                    "unauthorized database access, data extraction, or manipulation."
                ),
                evidence="SQL injection payload triggered abnormal response",
                remediation=[
                    "Use parameterized queries/prepared statements",
                    "Implement input validation and sanitization",
                    "Apply principle of least privilege for database accounts",
                    "Use ORM frameworks with built-in protection",
                    "Implement Web Application Firewall (WAF)",
                ],
                cwe_id="CWE-89",
                cvss_score=9.8,
            )
            vulnerabilities.append(vuln)

        # Test NoSQL Injection
        if await self._test_nosql_injection(url, method):
            vuln = self.create_vulnerability(
                name="NoSQL Injection Vulnerability",
                vuln_type=VulnerabilityType.BOPLA,
                severity=Severity.HIGH,
                endpoint=url,
                method=method,
                description=(
                    "The endpoint is vulnerable to NoSQL injection attacks. Malicious "
                    "query operators can bypass authentication or extract sensitive data."
                ),
                evidence="NoSQL injection payload successful",
                remediation=[
                    "Validate and sanitize all user inputs",
                    "Use schema validation",
                    "Avoid using user input in query operators",
                    "Implement input type checking",
                ],
                cwe_id="CWE-943",
                cvss_score=8.6,
            )
            vulnerabilities.append(vuln)

        # Test Command Injection
        if await self._test_command_injection(url, method):
            vuln = self.create_vulnerability(
                name="Command Injection Vulnerability",
                vuln_type=VulnerabilityType.BOPLA,
                severity=Severity.CRITICAL,
                endpoint=url,
                method=method,
                description=(
                    "The endpoint is vulnerable to OS command injection. Attackers can "
                    "execute arbitrary system commands on the server."
                ),
                evidence="Command injection indicators detected",
                remediation=[
                    "Never pass user input directly to system commands",
                    "Use language-specific APIs instead of shell commands",
                    "Implement strict input validation with whitelisting",
                    "Run applications with minimal privileges",
                ],
                cwe_id="CWE-78",
                cvss_score=9.9,
            )
            vulnerabilities.append(vuln)

        return vulnerabilities

    async def _test_sql_injection(self, url: str, method: str) -> bool:
        """Test for SQL injection vulnerabilities."""
        baseline = await self.client.request(method, url)

        for payload in self.SQL_PAYLOADS:
            # Test in URL parameters
            test_url = f"{url}?id={payload}"
            response = await self.client.request(method, test_url)

            # Check for SQL errors or abnormal responses
            if self._has_sql_error(response.body):
                return True

            if method in ["POST", "PUT", "PATCH"]:
                # Test in JSON body
                response = await self.client.request(
                    method, url, json={"input": payload, "id": payload}
                )
                if self._has_sql_error(response.body):
                    return True

        return False

    async def _test_nosql_injection(self, url: str, method: str) -> bool:
        """Test for NoSQL injection vulnerabilities."""
        for payload in self.NOSQL_PAYLOADS:
            if method in ["POST", "PUT", "PATCH"]:
                try:
                    import json
                    json_payload = json.loads(payload)
                    response = await self.client.request(method, url, json=json_payload)

                    # Successful authentication with injection indicates vulnerability
                    if 200 <= response.status_code < 300:
                        return True
                except:
                    pass

        return False

    async def _test_command_injection(self, url: str, method: str) -> bool:
        """Test for command injection vulnerabilities."""
        for payload in self.COMMAND_PAYLOADS:
            test_url = f"{url}?cmd={payload}"
            response = await self.client.request(method, test_url)

            # Look for command execution indicators
            if self._has_command_execution(response.body):
                return True

        return False

    def _has_sql_error(self, body: str) -> bool:
        """Check if response contains SQL error messages."""
        sql_errors = [
            "sql syntax",
            "mysql_fetch",
            "ora-",
            "postgresql",
            "sqlite_",
            "sqlexception",
            "syntax error",
            "unclosed quotation",
        ]
        body_lower = body.lower()
        return any(error in body_lower for error in sql_errors)

    def _has_command_execution(self, body: str) -> bool:
        """Check if response contains command execution indicators."""
        indicators = [
            "uid=",
            "gid=",
            "groups=",
            "root:",
            "/bin/",
            "/etc/passwd",
        ]
        return any(indicator in body for indicator in indicators)
