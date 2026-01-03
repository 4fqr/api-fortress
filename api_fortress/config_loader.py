"""
Configuration file support for API Fortress.
Loads scan configuration from YAML files.
"""

import yaml
from typing import Optional, Dict, Any
from pathlib import Path

from api_fortress.models import ScanConfig, AuthType
from pydantic import HttpUrl


class ConfigLoader:
    """Load and parse configuration files."""

    @staticmethod
    def load_from_file(config_path: str) -> ScanConfig:
        """Load configuration from YAML file."""
        path = Path(config_path)

        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        with open(path, "r", encoding="utf-8") as f:
            config_data = yaml.safe_load(f)

        return ConfigLoader.parse_config(config_data)

    @staticmethod
    def parse_config(config_data: Dict[str, Any]) -> ScanConfig:
        """Parse configuration dictionary into ScanConfig."""
        target = config_data.get("target", {})
        auth = config_data.get("authentication", {})
        scan = config_data.get("scan", {})

        # Build headers
        headers = target.get("headers", {})
        if auth.get("type") == "bearer" and auth.get("token"):
            headers["Authorization"] = f"Bearer {auth['token']}"
        elif auth.get("type") == "apikey" and auth.get("token"):
            headers["X-API-Key"] = auth["token"]

        return ScanConfig(
            target_url=HttpUrl(target.get("base_url")),
            methods=scan.get("methods", ["GET", "POST", "PUT", "DELETE"]),
            headers=headers,
            auth_type=AuthType(auth.get("type", "none")),
            auth_token=auth.get("token"),
            timeout=scan.get("timeout", 30),
            max_concurrent=scan.get("max_concurrent", 10),
            verify_ssl=scan.get("verify_ssl", True),
            exclude_paths=config_data.get("exclude", []),
        )

    @staticmethod
    def create_example_config(output_path: str) -> None:
        """Create an example configuration file."""
        example = """# API Fortress Configuration File
# Example configuration for API security scanning

target:
  base_url: "https://api.example.com"
  headers:
    User-Agent: "API-Fortress/1.0"
    Accept: "application/json"

authentication:
  type: "bearer"  # Options: bearer, basic, apikey, none
  token: "${API_TOKEN}"  # Use environment variable

scan:
  methods:
    - GET
    - POST
    - PUT
    - DELETE
    - PATCH
  
  timeout: 30
  max_concurrent: 10
  verify_ssl: true

# Endpoints to test (optional - if not specified, tests base_url)
endpoints:
  - path: "/api/v1/users"
    methods: ["GET", "POST"]
  - path: "/api/v1/admin"
    methods: ["GET"]
  - path: "/api/v1/products"
    methods: ["GET", "POST", "PUT", "DELETE"]

# Paths to exclude from scanning
exclude:
  - "/health"
  - "/metrics"
  - "/docs"

# Report configuration
report:
  format: "json"  # Options: json, html, markdown
  output: "security-report.json"
"""

        Path(output_path).write_text(example, encoding="utf-8")
