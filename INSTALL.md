# 🏰 API Fortress - Complete Installation & Usage Guide

## 📦 Installation

### Step 1: Install Python Dependencies

Open PowerShell in the project directory and run:

```powershell
# Install all required packages
pip install -r requirements.txt

# Install API Fortress as a package
pip install -e .
```

### Step 2: Verify Installation

```powershell
# Check if installation was successful
fortress --version

# Display help
fortress --help
```

You should see the API Fortress banner and help information.

---

## 🚀 Quick Start Examples

### Example 1: Basic Scan

```powershell
fortress scan https://api.example.com
```

### Example 2: Scan with Bearer Token Authentication

```powershell
fortress scan https://api.example.com --auth-type bearer --token "your-api-token-here"
```

### Example 3: Generate HTML Report

```powershell
fortress scan https://api.example.com --format html -o security-report.html
```

### Example 4: Full Featured Scan

```powershell
fortress scan https://api.example.com `
  --auth-type bearer `
  --token "your-token" `
  --methods GET,POST,PUT,DELETE `
  --header "X-Custom-Header: value" `
  --timeout 60 `
  --max-concurrent 5 `
  --format html `
  -o report.html `
  --exclude /health `
  --exclude /metrics `
  --verbose
```

---

## 🎯 Running the Demo

Test API Fortress with a live demo:

```powershell
python demo.py
```

This will:
- Scan a public test API
- Generate reports in JSON, HTML, and Markdown formats
- Demonstrate all features

---

## 📋 Command Reference

### Global Options

| Option | Description |
|--------|-------------|
| `--help` | Show help message |
| `--version` | Show version information |

### Scan Command Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--methods` | TEXT | GET,POST,PUT,DELETE,PATCH | HTTP methods to test |
| `-H, --header` | TEXT | - | Custom headers (repeatable) |
| `--auth-type` | CHOICE | none | Authentication type: bearer, basic, apikey, none |
| `-t, --token` | TEXT | - | Authentication token |
| `--timeout` | INT | 30 | Request timeout in seconds |
| `--max-concurrent` | INT | 10 | Maximum concurrent requests |
| `-o, --output` | PATH | - | Output file path |
| `--format` | CHOICE | json | Output format: json, html, markdown |
| `--no-verify-ssl` | FLAG | false | Disable SSL verification |
| `-v, --verbose` | FLAG | false | Enable verbose output |
| `--exclude` | TEXT | - | Paths to exclude (repeatable) |

---

## 🔐 Authentication Examples

### Bearer Token (JWT)

```powershell
fortress scan https://api.example.com `
  --auth-type bearer `
  --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### API Key

```powershell
fortress scan https://api.example.com `
  --auth-type apikey `
  --token "your-api-key-123456"
```

### Basic Authentication

```powershell
fortress scan https://api.example.com `
  --auth-type basic `
  --token "username:password"
```

### Custom Headers

```powershell
fortress scan https://api.example.com `
  -H "Authorization: Bearer token123" `
  -H "X-API-Key: key456" `
  -H "X-Custom-Header: value"
```

---

## 📊 Report Formats

### JSON Report (Machine-Readable)

```powershell
fortress scan https://api.example.com `
  --format json `
  -o report.json
```

**Best for:**
- CI/CD integration
- Automated processing
- API consumption

### HTML Report (Human-Readable)

```powershell
fortress scan https://api.example.com `
  --format html `
  -o report.html
```

**Best for:**
- Stakeholder presentations
- Security audits
- Documentation

**Features:**
- Beautiful, responsive design
- Color-coded severity levels
- Detailed vulnerability information
- Professional styling

### Markdown Report

```powershell
fortress scan https://api.example.com `
  --format markdown `
  -o report.md
```

**Best for:**
- GitHub/GitLab issues
- Documentation
- Quick sharing

---

## 🛡️ Vulnerability Coverage

API Fortress detects all **OWASP API Security Top 10** vulnerabilities:

| # | Vulnerability | Severity Range | Detection Method |
|---|---------------|----------------|------------------|
| 1 | Broken Object Level Authorization (BOLA) | HIGH-CRITICAL | ID manipulation, auth bypass testing |
| 2 | Broken Authentication | MEDIUM-CRITICAL | Token validation, session security |
| 3 | Broken Object Property Level Authorization | HIGH-CRITICAL | Injection testing, data exposure |
| 4 | Unrestricted Resource Access | MEDIUM-HIGH | Rate limiting detection |
| 5 | Broken Function Level Authorization | MEDIUM-HIGH | Privilege escalation testing |
| 6 | Unrestricted Business Flows | MEDIUM-HIGH | Business logic analysis |
| 7 | Server-Side Request Forgery (SSRF) | HIGH-CRITICAL | Internal resource access testing |
| 8 | Security Misconfiguration | LOW-HIGH | Header analysis, error handling |
| 9 | Improper Inventory Management | LOW-MEDIUM | API versioning checks |
| 10 | Unsafe Consumption of APIs | MEDIUM-HIGH | Third-party API risk analysis |

---

## 💡 Best Practices

### 1. Always Use Authentication

```powershell
# ✅ Good
fortress scan https://api.example.com --auth-type bearer --token "..."

# ❌ Bad (for authenticated APIs)
fortress scan https://api.example.com
```

### 2. Exclude Non-Critical Endpoints

```powershell
fortress scan https://api.example.com `
  --exclude /health `
  --exclude /metrics `
  --exclude /docs
```

### 3. Adjust Concurrency for Production

```powershell
# For production APIs (less aggressive)
fortress scan https://api.example.com --max-concurrent 3

# For testing environments (more aggressive)
fortress scan https://api.example.com --max-concurrent 20
```

### 4. Save Reports for Compliance

```powershell
fortress scan https://api.example.com `
  --format html `
  -o "reports/security-scan-$(Get-Date -Format 'yyyy-MM-dd').html"
```

---

## 🔧 Troubleshooting

### Issue: "Import errors" when running

**Solution:** Install dependencies

```powershell
pip install -r requirements.txt
pip install -e .
```

### Issue: SSL certificate errors

**Solution:** Use `--no-verify-ssl` flag

```powershell
fortress scan https://api.example.com --no-verify-ssl
```

### Issue: Timeout errors

**Solution:** Increase timeout

```powershell
fortress scan https://api.example.com --timeout 60
```

### Issue: Too many false positives

**Solution:** Review scanner configuration and adjust methods

```powershell
fortress scan https://api.example.com --methods GET,POST
```

---

## 📈 CI/CD Integration

### GitHub Actions Example

```yaml
name: API Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install API Fortress
        run: |
          pip install -r requirements.txt
          pip install -e .
      
      - name: Run Security Scan
        run: |
          fortress scan ${{ secrets.API_URL }} \
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

---

## 🎨 Features Showcase

### Beautiful Terminal Output

API Fortress provides:
- ✨ Stunning ASCII art banner
- 🎨 Color-coded severity levels
- 📊 Real-time progress bars
- 📋 Structured vulnerability displays
- 🛡️ Professional report generation

### Advanced Capabilities

- ⚡ **Asynchronous scanning** - Lightning-fast concurrent requests
- 🔐 **Universal authentication** - Supports all major auth types
- 🌐 **REST & GraphQL** - Works with any API architecture
- 📊 **Multiple report formats** - JSON, HTML, Markdown
- 🎯 **Heuristic analysis** - Smart vulnerability detection
- 🔧 **Highly configurable** - YAML config file support

---

## 📞 Support & Resources

- **Documentation**: See README.md and QUICKSTART.md
- **Examples**: Run `fortress examples`
- **Demo**: Run `python demo.py`
- **Issues**: Report bugs and request features on GitHub
- **Contributing**: See CONTRIBUTING.md

---

## ⚠️ Legal Disclaimer

**API Fortress is designed for authorized security testing only.**

- Always obtain proper authorization before testing any API
- Unauthorized testing may be illegal in your jurisdiction
- Users are solely responsible for their usage of this tool
- The developers assume no liability for misuse

---

## 🎓 Learning Resources

### Understanding OWASP API Top 10

1. [OWASP API Security Project](https://owasp.org/www-project-api-security/)
2. [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x00-header/)
3. [API Security Best Practices](https://owasp.org/www-project-api-security/)

### Recommended Reading

- API security fundamentals
- RESTful API design principles
- GraphQL security considerations
- Authentication and authorization patterns

---

**Built with 🛡️ by security professionals, for security professionals**

*API Fortress v1.0.0 - Professional API Security Testing Suite*
