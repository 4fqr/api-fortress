# Contributing to API Fortress

Thank you for your interest in contributing to API Fortress! This document provides guidelines and instructions for contributing.

## Development Setup

1. **Fork and clone the repository**

```bash
git clone https://github.com/YOUR_USERNAME/api-fortress.git
cd api-fortress
```

2. **Create a virtual environment**

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install development dependencies**

```bash
pip install -r requirements.txt
pip install -e ".[dev]"
```

## Code Style

- We use **Black** for code formatting
- We use **Ruff** for linting
- We use **MyPy** for type checking

Run before committing:

```bash
black api_fortress/
ruff check api_fortress/
mypy api_fortress/
```

## Project Structure

```
api_fortress/
├── __init__.py          # Package initialization
├── cli.py               # Command-line interface
├── models.py            # Data models
├── scanner.py           # Main scanner engine
├── http_client.py       # HTTP client
├── display.py           # Terminal UI
├── reporting.py         # Report generation
├── config_loader.py     # Configuration loader
└── scanners/            # Vulnerability scanners
    ├── __init__.py
    ├── bola_scanner.py
    ├── auth_scanner.py
    ├── injection_scanner.py
    ├── misconfig_scanner.py
    └── ssrf_scanner.py
```

## Adding New Scanners

To add a new vulnerability scanner:

1. Create a new file in `api_fortress/scanners/`
2. Inherit from `BaseScanner`
3. Implement the `scan()` method
4. Add scanner to `FortressScanner` in `scanner.py`

Example:

```python
from api_fortress.scanners import BaseScanner
from api_fortress.models import Vulnerability, Severity, VulnerabilityType

class NewScanner(BaseScanner):
    async def scan(self, url: str, method: str) -> List[Vulnerability]:
        vulnerabilities = []
        
        # Your detection logic here
        
        return vulnerabilities
```

## Testing

Run the demo to test your changes:

```bash
python demo.py
```

Test the CLI:

```bash
fortress scan https://jsonplaceholder.typicode.com
```

## Pull Request Process

1. Create a feature branch: `git checkout -b feature/your-feature`
2. Make your changes
3. Run tests and linting
4. Commit with clear messages
5. Push to your fork
6. Create a Pull Request

## Commit Message Format

```
type(scope): brief description

Detailed explanation if needed

Fixes #issue_number
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Test additions or changes
- `chore`: Build process or auxiliary tool changes

## Code Review

All submissions require review. We use GitHub pull requests for this purpose.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
