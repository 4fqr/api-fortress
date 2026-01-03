# 🏰 API Fortress - Quick Command Reference

## How to Run API Fortress

### Option 1: Using Python Script (Recommended for Windows)
```powershell
python fortress.py scan <URL> [OPTIONS]
```

### Option 2: Using Batch File
```powershell
.\fortress.bat scan <URL> [OPTIONS]
```

### Option 3: Using Python Module
```powershell
python -m api_fortress.cli scan <URL> [OPTIONS]
```

---

## Quick Examples

### 1. Basic Scan
```powershell
python fortress.py scan https://api.example.com
```

### 2. Scan Specific Methods
```powershell
python fortress.py scan https://api.example.com --methods GET,POST
```

### 3. Scan with Authentication
```powershell
python fortress.py scan https://api.example.com --auth-type bearer --token "YOUR_TOKEN"
```

### 4. Generate HTML Report
```powershell
python fortress.py scan https://api.example.com --format html -o report.html
```

### 5. Custom Headers
```powershell
python fortress.py scan https://api.example.com -H "Authorization: Bearer token" -H "X-API-Key: key"
```

### 6. Full Scan with All Options
```powershell
python fortress.py scan https://api.example.com `
  --auth-type bearer `
  --token "YOUR_TOKEN" `
  --methods GET,POST,PUT,DELETE `
  --timeout 60 `
  --max-concurrent 5 `
  --format html `
  -o security-report.html `
  --exclude /health `
  --exclude /metrics `
  --verbose
```

---

## Help Commands

```powershell
# Show help
python fortress.py --help

# Show scan options
python fortress.py scan --help

# Show examples
python fortress.py examples

# Show version
python fortress.py version
```

---

## Report Formats

### JSON (Default)
```powershell
python fortress.py scan <URL> --format json -o report.json
```

### HTML (Beautiful Web Report)
```powershell
python fortress.py scan <URL> --format html -o report.html
```

### Markdown (GitHub-Ready)
```powershell
python fortress.py scan <URL> --format markdown -o report.md
```

---

## Common Options

| Option | Short | Description | Example |
|--------|-------|-------------|---------|
| `--methods` | - | HTTP methods to test | `--methods GET,POST` |
| `--header` | `-H` | Custom header | `-H "Key: Value"` |
| `--auth-type` | - | Auth type | `--auth-type bearer` |
| `--token` | `-t` | Auth token | `-t "token123"` |
| `--timeout` | - | Request timeout | `--timeout 60` |
| `--max-concurrent` | - | Parallel requests | `--max-concurrent 10` |
| `--output` | `-o` | Output file | `-o report.html` |
| `--format` | - | Report format | `--format html` |
| `--verbose` | `-v` | Verbose output | `--verbose` |
| `--exclude` | - | Exclude paths | `--exclude /health` |

---

## Exit Codes

- `0` - Success, no critical/high vulnerabilities
- `1` - High severity vulnerabilities found
- `2` - Critical severity vulnerabilities found
- `3` - Scan error
- `130` - User interrupted (Ctrl+C)

---

## Tips

1. **Test Before Production**: Always test on staging/dev environments first
2. **Start Small**: Begin with single endpoint, then expand
3. **Use Authentication**: Include proper auth tokens for authenticated APIs
4. **Exclude Health Checks**: Use `--exclude` for non-critical endpoints
5. **Save Reports**: Always generate reports for documentation
6. **Review HTML**: HTML reports are most readable for stakeholders

---

## Demo

Run the included demo to see all features:

```powershell
python demo.py
```

This generates sample reports in JSON, HTML, and Markdown formats.

---

## Troubleshooting

### Command Not Found
If `fortress` command doesn't work, use:
```powershell
python fortress.py scan <URL>
```

### Import Errors
Reinstall dependencies:
```powershell
pip install -r requirements.txt
pip install -e .
```

### SSL Errors
Disable SSL verification:
```powershell
python fortress.py scan <URL> --no-verify-ssl
```

### Timeout Issues
Increase timeout:
```powershell
python fortress.py scan <URL> --timeout 120
```

---

**Made with 🛡️ by security professionals**
