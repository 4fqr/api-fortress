# 🏰 API Fortress - Quick Start Guide

## Installation

### Prerequisites
- Python 3.9 or higher
- pip package manager

### Install Dependencies

```powershell
# Navigate to project directory
cd CLI-API-Fortress

# Install required packages
pip install -r requirements.txt

# Install API Fortress as a package (editable mode)
pip install -e .
```

## Usage

### Basic Commands

```powershell
# Show help
fortress --help

# Scan an API
fortress scan https://api.example.com

# Scan with authentication
fortress scan https://api.example.com --auth-type bearer --token YOUR_TOKEN

# Show usage examples
fortress examples
```

### Command Options

```
Options:
  --methods TEXT              HTTP methods to test (default: GET,POST,PUT,DELETE,PATCH)
  -H, --header TEXT          Custom headers (format: 'Key: Value')
  --auth-type [bearer|basic|apikey|none]
                             Authentication type
  -t, --token TEXT           Authentication token
  --timeout INTEGER          Request timeout in seconds
  --max-concurrent INTEGER   Maximum concurrent requests
  -o, --output PATH          Output file path for report
  --format [json|html|markdown]
                             Report output format
  --no-verify-ssl            Disable SSL verification
  -v, --verbose              Enable verbose output
  --exclude TEXT             Paths to exclude from scanning
```

### Example Scans

```powershell
# Basic scan
fortress scan https://api.example.com

# Scan with Bearer authentication
fortress scan https://api.example.com --auth-type bearer --token "your-token-here"

# Scan specific methods and generate HTML report
fortress scan https://api.example.com --methods GET,POST --format html -o report.html

# Scan with custom headers
fortress scan https://api.example.com -H "Authorization: Bearer token" -H "X-API-Key: key"

# Full featured scan
fortress scan https://api.example.com `
  --auth-type bearer `
  --token YOUR_TOKEN `
  --methods GET,POST,PUT,DELETE `
  --timeout 60 `
  --format html `
  -o security-report.html `
  --exclude /health `
  --exclude /metrics `
  --verbose
```

## Run Demo

```powershell
# Run the demo against a public test API
python demo.py
```

This will:
- Scan a public API (jsonplaceholder.typicode.com)
- Generate sample reports in JSON, HTML, and Markdown formats
- Demonstrate the full capabilities of API Fortress

## Configuration File

Create a `fortress.yaml` configuration file:

```yaml
target:
  base_url: "https://api.example.com"
  
authentication:
  type: "bearer"
  token: "your-token-here"
  
scan:
  methods: ["GET", "POST", "PUT", "DELETE"]
  timeout: 30
  max_concurrent: 10

exclude:
  - "/health"
  - "/metrics"
```

## Report Formats

### JSON Report
```powershell
fortress scan https://api.example.com --format json -o report.json
```

### HTML Report (Interactive)
```powershell
fortress scan https://api.example.com --format html -o report.html
```

### Markdown Report
```powershell
fortress scan https://api.example.com --format markdown -o report.md
```

## Vulnerability Detection

API Fortress detects:

1. **Broken Object Level Authorization (BOLA)**
2. **Broken Authentication**
3. **Broken Object Property Level Authorization**
4. **Unrestricted Resource Access**
5. **Broken Function Level Authorization**
6. **Unrestricted Access to Sensitive Business Flows**
7. **Server-Side Request Forgery (SSRF)**
8. **Security Misconfiguration**
9. **Improper Inventory Management**
10. **Unsafe Consumption of APIs**

## Tips

- Always test with proper authorization
- Start with a single endpoint before scanning entire APIs
- Use `--exclude` to skip health checks and metrics endpoints
- Review reports in HTML format for best readability
- Use `--verbose` for detailed debugging information

## Exit Codes

- `0` - Scan completed, no critical/high vulnerabilities
- `1` - Scan completed, high severity vulnerabilities found
- `2` - Scan completed, critical severity vulnerabilities found
- `3` - Scan failed due to error
- `130` - Scan interrupted by user

## Support

For issues, questions, or contributions, visit:
https://github.com/api-fortress/api-fortress
