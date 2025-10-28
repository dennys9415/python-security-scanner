# Python Security Scanner

A professional, extensible security vulnerability scanner for Python applications.

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![CI/CD](https://github.com/dennys9415/python-security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/dennys9415/python-security-scanner/actions)

## Structure

```
python-security-scanner/
├── .github/
│   ├── workflows/
│   │   ├── ci.yml
│   │   └── security-scan.yml
│   └── ISSUE_TEMPLATE/
│       ├── bug_report.md
│       └── feature_request.md
├── src/
│   └── security_scanner/
│       ├── __init__.py
│       ├── core/
│       │   ├── __init__.py
│       │   ├── scanner.py
│       │   ├── vulnerability_detector.py
│       │   └── report_generator.py
│       ├── detectors/
│       │   ├── __init__.py
│       │   ├── sql_injection.py
│       │   ├── xss.py
│       │   ├── command_injection.py
│       │   └── file_inclusion.py
│       ├── utils/
│       │   ├── __init__.py
│       │   ├── helpers.py
│       │   └── logger.py
│       └── cli.py
├── tests/
│   ├── __init__.py
│   ├── test_scanner.py
│   ├── test_detectors.py
│   └── test_utils.py
├── docs/
│   ├── README.md
│   ├── CONTRIBUTING.md
│   ├── USAGE.md
│   └── API_REFERENCE.md
├── examples/
│   ├── basic_scan.py
│   ├── advanced_scan.py
│   └── custom_detector.py
├── requirements/
│   ├── base.txt
│   ├── dev.txt
│   └── prod.txt
├── .gitignore
├── .pre-commit-config.yaml
├── pyproject.toml
├── setup.py
├── LICENSE
└── README.md
```

## Features

- **Multiple Vulnerability Detection**: SQL Injection, XSS, Command Injection, Path Traversal
- **Extensible Architecture**: Easy to add custom detectors
- **Comprehensive Reporting**: JSON, HTML, and console reports
- **CLI and Programmatic Usage**: Use as command-line tool or Python library
- **Configurable Scanning**: Customize scan depth, targets, and detection rules

## Quick Start

### Installation

```bash
pip install python-security-scanner
```

## Basic Usage

```python
from security_scanner import SecurityScanner

scanner = SecurityScanner()
results = scanner.scan("path/to/your/code")
scanner.generate_report(results, "report.html")
```

## Command Line

```bash
# Scan a directory
security-scanner scan /path/to/project --output report.json

# Scan with specific detectors
security-scanner scan /path/to/project --detectors sql_injection,xss

# Get help
security-scanner --help
```

## Documentation

* Full Documentation
* Usage Guide
* API Reference
* Contributing

## Supported Vulnerabilities

* SQL Injection
* Cross-Site Scripting (XSS)
* Command Injection
* Local/Remote File Inclusion
* Path Traversal
* Insecure Deserialization
* Hardcoded Secrets

## License

This project is licensed under the MIT License - see the LICENSE file for details.