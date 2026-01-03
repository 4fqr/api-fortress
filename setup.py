"""
Setup script for API Fortress installation.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme = Path("README.md").read_text(encoding="utf-8")

setup(
    name="api-fortress",
    version="1.0.0",
    description="Professional-grade automated API security testing suite",
    long_description=readme,
    long_description_content_type="text/markdown",
    author="API Fortress Team",
    author_email="security@apifortress.dev",
    url="https://github.com/api-fortress/api-fortress",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "aiohttp>=3.9.0",
        "rich>=13.7.0",
        "click>=8.1.7",
        "pydantic>=2.5.0",
        "pyyaml>=6.0.1",
        "httpx>=0.25.0",
        "pyjwt>=2.8.0",
        "cryptography>=41.0.0",
        "validators>=0.22.0",
        "python-dotenv>=1.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.7.0",
            "mypy>=1.5.0",
            "ruff>=0.0.280",
        ],
    },
    entry_points={
        "console_scripts": [
            "fortress=api_fortress.cli:main",
            "api-fortress=api_fortress.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
    ],
    keywords=["api", "security", "testing", "owasp", "pentesting", "vulnerability-scanner"],
    project_urls={
        "Documentation": "https://docs.apifortress.dev",
        "Source": "https://github.com/api-fortress/api-fortress",
        "Bug Reports": "https://github.com/api-fortress/api-fortress/issues",
    },
)
