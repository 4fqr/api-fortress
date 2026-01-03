"""
Data models for API Fortress.
Defines security findings, configurations, and result structures.
"""

from typing import Optional, List, Dict, Any, Literal
from enum import Enum
from pydantic import BaseModel, Field, HttpUrl
from datetime import datetime


class Severity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnerabilityType(str, Enum):
    """OWASP API Security Top 10 vulnerability types."""

    BOLA = "Broken Object Level Authorization"
    BROKEN_AUTH = "Broken Authentication"
    BOPLA = "Broken Object Property Level Authorization"
    UNRESTRICTED_RESOURCE = "Unrestricted Resource Access"
    BFLA = "Broken Function Level Authorization"
    BUSINESS_FLOW = "Unrestricted Access to Sensitive Business Flows"
    SSRF = "Server-Side Request Forgery"
    SECURITY_MISCONFIG = "Security Misconfiguration"
    INVENTORY_MANAGEMENT = "Improper Inventory Management"
    UNSAFE_CONSUMPTION = "Unsafe Consumption of APIs"


class AuthType(str, Enum):
    """Supported authentication types."""

    BEARER = "bearer"
    BASIC = "basic"
    API_KEY = "apikey"
    OAUTH2 = "oauth2"
    CUSTOM = "custom"
    NONE = "none"


class Vulnerability(BaseModel):
    """Security vulnerability finding."""

    id: str = Field(description="Unique vulnerability identifier")
    name: str = Field(description="Vulnerability name")
    type: VulnerabilityType = Field(description="OWASP category")
    severity: Severity = Field(description="Severity level")
    endpoint: str = Field(description="Affected endpoint")
    method: str = Field(description="HTTP method")
    description: str = Field(description="Detailed description")
    evidence: Optional[str] = Field(None, description="Evidence/proof of vulnerability")
    remediation: List[str] = Field(default_factory=list, description="Mitigation steps")
    cwe_id: Optional[str] = Field(None, description="CWE identifier")
    cvss_score: Optional[float] = Field(None, description="CVSS score")
    timestamp: datetime = Field(default_factory=datetime.now)

    class Config:
        use_enum_values = True


class ScanConfig(BaseModel):
    """Scan configuration."""

    target_url: HttpUrl = Field(description="Target API base URL")
    methods: List[str] = Field(
        default=["GET", "POST", "PUT", "DELETE", "PATCH"], description="HTTP methods to test"
    )
    headers: Dict[str, str] = Field(default_factory=dict, description="Custom headers")
    auth_type: AuthType = Field(default=AuthType.NONE, description="Authentication type")
    auth_token: Optional[str] = Field(None, description="Authentication token")
    timeout: int = Field(default=30, description="Request timeout in seconds")
    max_concurrent: int = Field(default=10, description="Maximum concurrent requests")
    verify_ssl: bool = Field(default=True, description="Verify SSL certificates")
    user_agent: str = Field(
        default="API-Fortress/1.0 (Security Scanner)", description="User agent string"
    )
    openapi_spec: Optional[HttpUrl] = Field(None, description="OpenAPI/Swagger spec URL")
    exclude_paths: List[str] = Field(default_factory=list, description="Paths to exclude")

    class Config:
        use_enum_values = True


class EndpointTest(BaseModel):
    """Test case for an endpoint."""

    path: str
    method: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    body: Optional[Dict[str, Any]] = None
    expected_status: List[int] = Field(default_factory=lambda: [200])


class ScanResult(BaseModel):
    """Complete scan results."""

    scan_id: str = Field(description="Unique scan identifier")
    target: str = Field(description="Target URL")
    start_time: datetime = Field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    duration: Optional[float] = None
    total_requests: int = Field(default=0)
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    endpoints_tested: int = Field(default=0)
    config: ScanConfig

    def get_severity_counts(self) -> Dict[str, int]:
        """Count vulnerabilities by severity."""
        counts = {severity.value.lower(): 0 for severity in Severity}
        for vuln in self.vulnerabilities:
            counts[vuln.severity.lower()] += 1
        return counts

    def get_risk_score(self) -> float:
        """Calculate overall risk score (0-100)."""
        severity_weights = {
            "CRITICAL": 10.0,
            "HIGH": 7.5,
            "MEDIUM": 5.0,
            "LOW": 2.5,
            "INFO": 1.0,
        }
        total_score = sum(severity_weights.get(v.severity, 0) for v in self.vulnerabilities)
        return min(total_score, 100.0)


class HTTPResponse(BaseModel):
    """HTTP response wrapper."""

    status_code: int
    headers: Dict[str, str]
    body: str
    elapsed_time: float
    url: str

    class Config:
        arbitrary_types_allowed = True
