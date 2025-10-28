# Usage Guide

## Installation

```bash
pip install python-security-scanner
```

Or install from source:

```bash
git clone https://github.com/your-username/python-security-scanner
cd python-security-scanner
pip install -e .
```

## Basic Usage

### Command Line

Scan a directory:

```bash
security-scanner scan /path/to/your/project
```

Scan with specific output format:

```bash
security-scanner scan /path/to/project --output report.html --format html
```

### Python API

```python
from security_scanner import SecurityScanner

scanner = SecurityScanner()
vulnerabilities = scanner.scan("/path/to/your/code")

# Generate reports
scanner.generate_report(vulnerabilities, "report.json", "json")
scanner.generate_report(vulnerabilities, "report.html", "html")
```

## Configuration

Create a configuration file:

```bash
security-scanner init --output config.yaml
```

Edit the generated config.yaml to customize scanning behavior.

## Supported Detectors

* SQL Injection
* Cross-Site Scripting (XSS)
* Command Injection
* File Inclusion
* Hardcoded Secrets
* Insecure Deserialization

## Examples

See the examples/ directory for more usage examples.