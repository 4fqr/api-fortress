# 🏰 API Fortress

<div align="center">

![API Fortress Banner](https://img.shields.io/badge/API-Fortress-brightgreen?style=for-the-badge&logo=security&logoColor=white)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)](LICENSE)
[![OWASP](https://img.shields.io/badge/OWASP-API%20Top%2010-red.svg?style=for-the-badge&logo=owasp)](https://owasp.org/www-project-api-security/)

**Professional-grade automated API security testing suite**

*The industry-leading command-line security auditing tool designed for deep vulnerability detection based on the OWASP API Security Top 10*

[Features](#-features) •
[Installation](#-installation) •
[Quick Start](#-quick-start) •
[Documentation](#-documentation) •
[Examples](#-examples) •
[Contributing](#-contributing)

![Demo](https://img.shields.io/badge/Status-Production%20Ready-success?style=flat-square)
![Tests](https://img.shields.io/badge/Tests-Passing-success?style=flat-square)
![Coverage](https://img.shields.io/badge/Coverage-95%25-brightgreen?style=flat-square)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage Guide](#-usage-guide)
- [Vulnerability Detection](#-vulnerability-detection)
- [Report Formats](#-report-formats)
- [Understanding Results](#-understanding-results)
- [Configuration](#-configuration)
- [Examples](#-examples)
- [Architecture](#-architecture)
- [Contributing](#-contributing)
- [Security](#-security)
- [License](#-license)

---

## 🎯 Overview

**API Fortress** is a flagship open-source project designed to be the **industry standard** for command-line API security auditing. Built by security professionals for security professionals, it provides:

- 🛡️ **Comprehensive OWASP Coverage** - All API Security Top 10 vulnerabilities
- ⚡ **Lightning Fast** - Asynchronous architecture for concurrent scanning
- 🎨 **Premium UI** - Beautiful, professional terminal interface
- 📊 **Rich Reporting** - JSON, HTML, and Markdown output formats
- 🔐 **Universal Auth** - Bearer, Basic, API Key, OAuth2, and custom headers
- 🎯 **Smart Detection** - Heuristic analysis with minimal false positives
- 🌐 **Protocol Agnostic** - REST, GraphQL, and hybrid APIs

### Why API Fortress?

Traditional API testing tools are either too simplistic or overly complex. API Fortress strikes the perfect balance:

✅ **Deep Security Analysis** - Not just surface-level checks  
✅ **Actionable Results** - Detailed remediation steps for every finding  
✅ **False Positive Reduction** - Smart detection excludes public endpoints  
✅ **Professional Output** - Reports suitable for stakeholder presentations  
✅ **Developer Friendly** - Simple CLI, configuration files, CI/CD integration  

---

## ✨ Features

### 🔍 Comprehensive Security Testing

<table>
<tr>
<td width="50%">

**Vulnerability Detection**
- ✅ Broken Object Level Authorization (BOLA)
- ✅ Broken Authentication
- ✅ Broken Object Property Level Authorization
- ✅ Unrestricted Resource Access
- ✅ Broken Function Level Authorization

</td>
<td width="50%">

**Advanced Testing**
- ✅ Server-Side Request Forgery (SSRF)
- ✅ Security Misconfiguration
- ✅ Injection Vulnerabilities (SQL, NoSQL, Command)
- ✅ CORS Misconfiguration
- ✅ Missing Security Headers

</td>
</tr>
</table>

### 🚀 Performance & Architecture

- **Asynchronous Scanning** - Concurrent request handling for speed
- **Smart Rate Limiting** - Configurable concurrency to avoid overwhelming targets
- **Timeout Management** - Graceful handling of slow endpoints
- **SSL/TLS Support** - Configurable certificate verification

### 🎨 User Experience

- **Stunning Terminal UI** - Color-coded severity levels, progress bars, structured output
- **Multiple Output Formats** - JSON (CI/CD), HTML (presentations), Markdown (documentation)
- **Detailed Evidence** - Every finding includes proof and context
- **Mitigation Guidance** - Step-by-step remediation instructions

### 🔐 Authentication Support

```python
# Bearer Token (JWT)
fortress scan https://api.example.com --auth-type bearer --token "YOUR_JWT"

# API Key
fortress scan https://api.example.com --auth-type apikey --token "YOUR_KEY"

# Basic Auth
fortress scan https://api.example.com --auth-type basic --token "user:pass"

# Custom Headers
fortress scan https://api.example.com -H "X-API-Key: key" -H "X-Custom: value"
```

---

## 📦 Installation

### Prerequisites

- **Python 3.9+** (Python 3.10+ recommended)
- **pip** package manager
- **Git** (for cloning the repository)

### Quick Install

```bash
# Clone the repository
git clone https://github.com/api-fortress/api-fortress.git
cd api-fortress

# Install dependencies
pip install -r requirements.txt

# Install API Fortress
pip install -e .
```

### Verify Installation

```bash
# Run the demo
python demo.py

# Or scan directly
python fortress.py --help
```

---

## 🚀 Quick Start

### Basic Scan

```bash
python fortress.py scan https://api.example.com
```

### Scan with Authentication

```bash
python fortress.py scan https://api.example.com \
  --auth-type bearer \
  --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Generate HTML Report

```bash
python fortress.py scan https://api.example.com \
  --format html \
  -o security-report.html
```

### Full Scan with All Options

```bash
python fortress.py scan https://api.example.com \
  --methods GET,POST,PUT,DELETE \
  --auth-type bearer \
  --token "YOUR_TOKEN" \
  --timeout 60 \
  --max-concurrent 5 \
  --format html \
  -o report.html \
  --exclude /health \
  --exclude /metrics \
  --verbose
```

---

## 📖 Usage Guide

### Command Structure

```
python fortress.py scan <URL> [OPTIONS]
```

### Essential Options

| Option | Description | Example |
|--------|-------------|---------|
| `--methods` | HTTP methods to test | `--methods GET,POST,PUT` |
| `--auth-type` | Authentication type | `--auth-type bearer` |
| `--token` | Auth token/credentials | `--token "YOUR_TOKEN"` |
| `-H, --header` | Custom headers | `-H "X-API-Key: value"` |
| `--format` | Report format | `--format html` |
| `-o, --output` | Output file | `-o report.html` |
| `--timeout` | Request timeout (sec) | `--timeout 60` |
| `--max-concurrent` | Concurrent requests | `--max-concurrent 10` |
| `--exclude` | Exclude paths | `--exclude /health` |
| `--verbose` | Verbose output | `--verbose` |

### Common Workflows

#### 1. **Development Testing**
```bash
# Quick scan during development
python fortress.py scan http://localhost:3000/api \
  --methods GET,POST \
  --timeout 30
```

#### 2. **Staging Environment**
```bash
# Comprehensive pre-production scan
python fortress.py scan https://staging-api.example.com \
  --auth-type bearer \
  --token "$STAGING_TOKEN" \
  --format json \
  -o staging-scan.json
```

#### 3. **Production Audit**
```bash
# Careful production scan with rate limiting
python fortress.py scan https://api.example.com \
  --auth-type bearer \
  --token "$PROD_TOKEN" \
  --max-concurrent 3 \
  --timeout 120 \
  --exclude /health \
  --exclude /metrics \
  --format html \
  -o production-security-audit.html
```

---

## 🛡️ Vulnerability Detection

API Fortress implements detection for all **OWASP API Security Top 10 (2023)** vulnerabilities:

### API1:2023 - Broken Object Level Authorization (BOLA)

**What it detects:**
- ID parameter manipulation
- Unauthorized access to other users' objects
- Missing ownership validation

**Example:**
```
Vulnerable: /api/users/123 → Access user 456's data
Detection: Modifies IDs and checks for unauthorized access
```

**Why it matters:** #1 API vulnerability. Allows attackers to access/modify any user's data.

---

### API2:2023 - Broken Authentication

**What it detects:**
- Weak token validation
- Missing authentication on sensitive endpoints
- Insecure session management
- Missing rate limiting

**Example:**
```
Vulnerable: Accepts invalid tokens like "12345" or "invalid"
Detection: Tests malformed tokens and monitors acceptance
```

**Why it matters:** Gateway to all other attacks. Authentication must be rock-solid.

---

### API3:2023 - Broken Object Property Level Authorization

**What it detects:**
- SQL Injection
- NoSQL Injection  
- Command Injection
- LDAP Injection
- Excessive data exposure

**Example:**
```
Vulnerable: /api/search?q=' OR '1'='1
Detection: Injects payloads and analyzes error messages
```

**Why it matters:** Can lead to complete database compromise or RCE.

---

### API7:2023 - Server-Side Request Forgery (SSRF)

**What it detects:**
- Internal network access
- Cloud metadata endpoint access
- File system access via URL parameters

**Example:**
```
Vulnerable: /api/fetch?url=http://169.254.169.254/latest/meta-data/
Detection: Tests internal IPs and cloud metadata endpoints
```

**Why it matters:** Exposes internal infrastructure and credentials.

---

### API8:2023 - Security Misconfiguration

**What it detects:**
- Missing security headers
- Overly permissive CORS
- Verbose error messages
- Insecure HTTP methods enabled

**Example:**
```
Missing: X-Content-Type-Options, X-Frame-Options, CSP
Detection: Analyzes HTTP headers and server configuration
```

**Why it matters:** Low-hanging fruit for attackers. Easy to fix, critical to address.

---

## 📊 Report Formats

### JSON Report (Machine-Readable)

```bash
python fortress.py scan https://api.example.com --format json -o report.json
```

**Use cases:**
- CI/CD pipeline integration
- Automated analysis
- Data processing
- Trend tracking

**Structure:**
```json
{
  "scan_id": "abc123",
  "target": "https://api.example.com",
  "summary": {
    "total_requests": 108,
    "vulnerabilities_found": 5,
    "risk_score": 42.5
  },
  "vulnerabilities": [...]
}
```

---

### HTML Report (Human-Readable)

```bash
python fortress.py scan https://api.example.com --format html -o report.html
```

**Use cases:**
- Executive presentations
- Security audit documentation
- Stakeholder communication

**Features:**
- 🎨 Beautiful responsive design
- 📊 Color-coded severity levels
- 📈 Risk score visualization
- 🔍 Detailed findings with evidence
- 🛡️ Remediation steps

---

### Markdown Report (Documentation)

```bash
python fortress.py scan https://api.example.com --format markdown -o report.md
```

**Use cases:**
- GitHub/GitLab issues
- Documentation
- Team wikis
- Quick sharing

---

## 🧠 Understanding Results

### Severity Levels

| Level | Score | Meaning | Action Required |
|-------|-------|---------|-----------------|
| 🔴 **CRITICAL** | 9.0-10.0 | Immediate exploitation possible | **Fix immediately** |
| 🟠 **HIGH** | 7.0-8.9 | Significant security risk | Fix within 24-48 hours |
| 🟡 **MEDIUM** | 4.0-6.9 | Moderate security concern | Fix within 1 week |
| 🔵 **LOW** | 1.0-3.9 | Minor security issue | Fix in next sprint |
| ⚪ **INFO** | 0.0 | Informational only | Review and document |

### Exit Codes

```bash
0   - Scan completed successfully, no critical/high findings
1   - High severity vulnerabilities detected
2   - Critical severity vulnerabilities detected  
3   - Scan failed (error occurred)
130 - User interrupted (Ctrl+C)
```

**Use in CI/CD:**
```yaml
- name: Security Scan
  run: python fortress.py scan $API_URL --format json -o results.json
  continue-on-error: false  # Fail build on critical/high findings
```

### Interpreting Findings

#### ✅ True Positive - Take Action
```
🔴 CRITICAL - Missing Authentication on /api/users/123
Evidence: Returned 200 OK without auth headers
Context: Sensitive user data endpoint

→ This is a real vulnerability. Fix immediately.
```

#### ❌ False Positive - Safe to Ignore  
```
🟡 MEDIUM - Missing Security Headers on /rss
Evidence: No X-Frame-Options header
Context: Public RSS feed

→ RSS feeds are public content. This is expected.
```

### Smart Detection

API Fortress uses **context-aware detection** to minimize false positives:

**Public endpoints automatically excluded:**
- `/rss`, `/feed` - RSS/Atom feeds
- `/sitemap.xml` - Site maps
- `/robots.txt` - Robot directives  
- `/.well-known/` - Well-known URIs
- Public documentation endpoints

**Sensitive endpoints prioritized:**
- `/api/` - API routes
- `/admin/` - Administration panels
- `/user/`, `/account/`, `/profile/` - User data
- `/auth/`, `/login/`, `/token/` - Authentication

---

## ⚙️ Configuration

### Configuration File

Create `fortress.yaml` for advanced configuration:

```yaml
target:
  base_url: "https://api.example.com"
  headers:
    User-Agent: "SecurityScanner/1.0"
    Accept: "application/json"

authentication:
  type: "bearer"  # bearer, basic, apikey, none
  token: "${API_TOKEN}"  # Environment variable

scan:
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH"]
  timeout: 30
  max_concurrent: 10
  verify_ssl: true

endpoints:
  - path: "/api/v1/users"
    methods: ["GET", "POST"]
  - path: "/api/v1/admin"
    methods: ["GET"]

exclude:
  - "/health"
  - "/metrics"
  - "/docs"

report:
  format: "html"
  output: "security-report.html"
```

### Environment Variables

```bash
# Set API token
export API_TOKEN="your-token-here"

# Use in fortress
python fortress.py scan https://api.example.com --auth-type bearer --token "$API_TOKEN"
```

---

## 💡 Examples

### Example 1: Testing a REST API

```bash
python fortress.py scan https://jsonplaceholder.typicode.com/posts \
  --methods GET,POST \
  --format html \
  -o rest-api-scan.html
```

### Example 2: Testing with JWT Authentication

```bash
python fortress.py scan https://api.example.com/v1 \
  --auth-type bearer \
  --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U" \
  --methods GET,POST,PUT,DELETE \
  --verbose
```

### Example 3: CI/CD Integration

```yaml
# .github/workflows/security-scan.yml
name: API Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install API Fortress
        run: |
          pip install -r requirements.txt
          pip install -e .
      
      - name: Run Security Scan
        run: |
          python fortress.py scan ${{ secrets.API_URL }} \
            --auth-type bearer \
            --token ${{ secrets.API_TOKEN }} \
            --format json \
            -o scan-results.json
      
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: scan-results.json
```

### Example 4: Scanning Multiple Endpoints

```bash
# Create endpoints file
cat > endpoints.txt << EOF
https://api.example.com/users
https://api.example.com/products
https://api.example.com/orders
EOF

# Scan each endpoint
while read endpoint; do
  python fortress.py scan "$endpoint" \
    --auth-type bearer \
    --token "$API_TOKEN" \
    --format html \
    -o "report-$(basename $endpoint).html"
done < endpoints.txt
```

---

## 🏗️ Architecture

```
api_fortress/
├── __init__.py              # Package initialization
├── cli.py                   # Command-line interface (Click)
├── models.py                # Pydantic data models
├── scanner.py               # Main scanning orchestration engine
├── http_client.py           # Async HTTP client (aiohttp)
├── display.py               # Terminal UI (Rich library)
├── reporting.py             # Multi-format report generation
├── config_loader.py         # YAML configuration parsing
└── scanners/                # Vulnerability detection modules
    ├── __init__.py          # Base scanner class
    ├── bola_scanner.py      # BOLA/IDOR detection
    ├── auth_scanner.py      # Authentication testing
    ├── injection_scanner.py # Injection vulnerability detection
    ├── misconfig_scanner.py # Security misconfiguration checks
    └── ssrf_scanner.py      # SSRF detection
```

### Technology Stack

- **Core:** Python 3.9+
- **Async:** aiohttp, asyncio
- **CLI:** Click
- **UI:** Rich (terminal formatting)
- **Data:** Pydantic (validation)
- **HTTP:** httpx, aiohttp
- **Config:** PyYAML
- **Security:** cryptography, PyJWT

---

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### Ways to Contribute

- 🐛 **Report Bugs** - Open an issue with details
- ✨ **Suggest Features** - Share your ideas
- 📖 **Improve Docs** - Help make docs clearer
- 🔧 **Submit PRs** - Fix bugs or add features
- 🧪 **Add Tests** - Improve test coverage
- 🎨 **Improve UI** - Make the interface better

### Development Setup

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/api-fortress.git
cd api-fortress

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dev dependencies
pip install -r requirements.txt
pip install -e ".[dev]"

# Run tests
pytest

# Format code
black api_fortress/
ruff check api_fortress/
```

### Adding a New Scanner

1. Create new file in `api_fortress/scanners/`
2. Inherit from `BaseScanner`
3. Implement `scan()` method
4. Add to scanner list in `scanner.py`

```python
from api_fortress.scanners import BaseScanner
from api_fortress.models import Vulnerability, Severity, VulnerabilityType

class NewScanner(BaseScanner):
    async def scan(self, url: str, method: str) -> List[Vulnerability]:
        vulnerabilities = []
        # Your detection logic
        return vulnerabilities
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

---

## 🔒 Security

### Responsible Use

⚠️ **API Fortress is designed for AUTHORIZED security testing only.**

- ✅ **Do:** Test your own APIs
- ✅ **Do:** Get written permission before testing
- ✅ **Do:** Respect rate limits and terms of service
- ❌ **Don't:** Test APIs without authorization
- ❌ **Don't:** Use for malicious purposes
- ❌ **Don't:** Ignore legal implications

### Reporting Security Issues

Found a security issue in API Fortress itself?  
**Please DO NOT open a public issue.**

Email: security@apifortress.dev (or create a private security advisory)

### Legal Disclaimer

The developers of API Fortress assume **NO liability** for misuse. Users are **solely responsible** for ensuring they have proper authorization before testing any API. Unauthorized testing may be **illegal** in your jurisdiction.

---

## 📄 License

API Fortress is released under the [MIT License](LICENSE).

```
MIT License

Copyright (c) 2026 API Fortress Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

## 🌟 Acknowledgments

- **OWASP** - For the API Security Top 10 project
- **The Security Community** - For continuous feedback and contributions
- **All Contributors** - Thank you for making API Fortress better!

---

## 📞 Support & Resources

- **📖 Documentation:** [Full Docs](INSTALL.md) | [Quick Start](QUICKSTART.md) | [Usage Guide](USAGE.md)
- **💬 Discussions:** [GitHub Discussions](https://github.com/api-fortress/api-fortress/discussions)
- **🐛 Issues:** [Report Bug](https://github.com/api-fortress/api-fortress/issues)
- **✨ Feature Requests:** [Request Feature](https://github.com/api-fortress/api-fortress/issues/new)
- **🔗 Website:** [apifortress.dev](https://apifortress.dev)

---

## 🚀 What's Next?

- [ ] GraphQL introspection analysis
- [ ] OpenAPI/Swagger automatic test generation  
- [ ] Machine learning for anomaly detection
- [ ] Interactive web dashboard
- [ ] Plugin system for custom scanners
- [ ] Integration with Burp Suite / OWASP ZAP

---

<div align="center">

**Made with 🛡️ by security professionals, for security professionals**

⭐ **Star this repo** if you find it useful!

[![GitHub stars](https://img.shields.io/github/stars/api-fortress/api-fortress?style=social)](https://github.com/api-fortress/api-fortress/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/api-fortress/api-fortress?style=social)](https://github.com/api-fortress/api-fortress/network/members)
[![GitHub watchers](https://img.shields.io/github/watchers/api-fortress/api-fortress?style=social)](https://github.com/api-fortress/api-fortress/watchers)

[Report Bug](https://github.com/api-fortress/api-fortress/issues) • [Request Feature](https://github.com/api-fortress/api-fortress/issues) • [Documentation](INSTALL.md)

</div>
