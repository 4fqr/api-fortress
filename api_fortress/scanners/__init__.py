"""
Base scanner class and common utilities.
"""

from typing import List, Optional
from abc import ABC, abstractmethod
import uuid

from api_fortress.models import Vulnerability, HTTPResponse, Severity, VulnerabilityType
from api_fortress.http_client import FortressHTTPClient


class BaseScanner(ABC):
    """Base class for all vulnerability scanners."""

    def __init__(self, client: FortressHTTPClient):
        self.client = client
        self.vulnerabilities: List[Vulnerability] = []

    @abstractmethod
    async def scan(self, url: str, method: str) -> List[Vulnerability]:
        """Execute scan and return vulnerabilities."""
        pass

    def create_vulnerability(
        self,
        name: str,
        vuln_type: VulnerabilityType,
        severity: Severity,
        endpoint: str,
        method: str,
        description: str,
        evidence: Optional[str] = None,
        remediation: Optional[List[str]] = None,
        cwe_id: Optional[str] = None,
        cvss_score: Optional[float] = None,
    ) -> Vulnerability:
        """Helper to create vulnerability object."""
        return Vulnerability(
            id=str(uuid.uuid4()),
            name=name,
            type=vuln_type,
            severity=severity,
            endpoint=endpoint,
            method=method,
            description=description,
            evidence=evidence,
            remediation=remediation or [],
            cwe_id=cwe_id,
            cvss_score=cvss_score,
        )

    def add_vulnerability(self, vuln: Vulnerability) -> None:
        """Add vulnerability to the list."""
        self.vulnerabilities.append(vuln)

    def get_vulnerabilities(self) -> List[Vulnerability]:
        """Get all detected vulnerabilities."""
        return self.vulnerabilities
