# Python Security Scanner Documentation

## Overview

The Python Security Scanner is a comprehensive static analysis tool designed to identify security vulnerabilities in Python code. It uses abstract syntax tree (AST) analysis to detect potential security issues before they reach production.

## Table of Contents

- [Installation](./README.md#installation)
- [Quick Start](./README.md#quick-start)
- [Configuration](./README.md#configuration)
- [Detectors](./README.md#detectors)
- [Reports](./README.md#reports)
- [API Reference](./API_REFERENCE.md)
- [Contributing](./CONTRIBUTING.md)

## Installation

### From PyPI

```bash
pip install python-security-scanner
```

### From Source

```bash
git clone https://github.com/your-username/python-security-scanner
cd python-security-scanner
pip install -e .
```

### Development Installation

```bash
pip install -e .[dev]
pre-commit install
```

## Quick Start

### Command Line Interface

```bash
# Scan a directory
security-scanner scan /path/to/your/project

# Scan with HTML report
security-scanner scan /path/to/project --output report.html --format html

# Scan with specific detectors
security-scanner scan /path/to/project --detectors sql_injection,command_injection

# Generate configuration file
security-scanner init --output config.yaml
```

### Python API

```python
from security_scanner import SecurityScanner

# Initialize scanner
scanner = SecurityScanner()

# Scan a directory or file
vulnerabilities = scanner.scan("/path/to/your/code")

# Generate reports
scanner.generate_report(vulnerabilities, "security_report.json", "json")
scanner.generate_report(vulnerabilities, "security_report.html", "html")

# Print summary
print(f"Found {len(vulnerabilities)} vulnerabilities")
```

## Configuration

The scanner can be configured using a YAML file:

```yaml
scan:
  exclude_dirs:
    - .git
    - __pycache__
    - venv
    - .env
  max_file_size: 10485760
  follow_symlinks: false

detectors:
  sql_injection:
    enabled: true
  xss:
    enabled: true
  command_injection:
    enabled: true
  file_inclusion:
    enabled: true
  hardcoded_secrets:
    enabled: true
  insecure_deserialization:
    enabled: true

reporting:
  min_severity: Low
  include_code_snippets: true
  output_formats:
    - console
    - html
    - json
```

Generate a default configuration:

```bash
security-scanner init --output config.yaml
```

## Detectors

### SQL Injection Detector

Detects: Unsafe SQL query construction using string formatting
Severity: High
Example:

```python
# Vulnerable
cursor.execute("SELECT * FROM users WHERE name = '%s'" % user_input)

# Safe
cursor.execute("SELECT * FROM users WHERE name = ?", (user_input,))
```

### Command Injection Detector

Detects: Unsafe command execution with user input
Severity: Critical
Example:

```python
# Vulnerable
os.system(f"echo {user_input}")

# Safe
subprocess.run(["echo", user_input], shell=False)
```

### Cross-Site Scripting (XSS) Detector

Detects: Unsafe template rendering with user input
Severity: High
Example:

```python
# Vulnerable (Flask/Jinja2)
return render_template_string(user_input)

# Safe
return render_template("template.html", data=escape(user_input))
```

### File Inclusion Detector

Detects: Unsafe file operations with user-controlled paths
Severity: Medium
Example:

```python
# Vulnerable
with open(user_input, 'w') as f:
    f.write(data)

# Safe
safe_path = os.path.basename(user_input)
with open(safe_path, 'w') as f:
    f.write(data)
```

### Hardcoded Secrets Detector

Detects: Passwords, API keys, and tokens in source code
Severity: High
Example:

```python
# Vulnerable
API_KEY = "sk-1234567890abcdef"

# Safe
API_KEY = os.getenv("API_KEY")
```

### Insecure Deserialization Detector

Detects: Unsafe deserialization of untrusted data
Severity: High
Example:

```python
# Vulnerable
import pickle
data = pickle.loads(user_input)

# Safe
import json
data = json.loads(user_input)
```

## Reports

### HTML Reports

HTML reports provide a visually rich interface with:

* Color-coded severity levels
* Code snippets
* File navigation
* Summary statistics

### JSON Reports

JSON reports are machine-readable and include:

* Complete vulnerability data
* Metadata about the scan
* Structured format for integration with other tools

### Console Reports

Console reports provide immediate feedback with:

* Color-coded output
* Brief vulnerability descriptions
* Quick overview of findings

## Integration

### CI/CD Pipelines

Integrate the scanner into your CI/CD pipeline:

```yaml
# GitHub Actions example
- name: Security Scan
  run: |
    pip install python-security-scanner
    security-scanner scan . --output security-report.json --format json
```

### Pre-commit Hook

Add to your .pre-commit-config.yaml:

```yaml
repos:
  - repo: local
    hooks:
      - id: security-scan
        name: Security Scan
        entry: security-scanner
        args: [scan, .]
        language: system
        pass_filenames: false
```

## Performance

The scanner is optimized for performance:

* Parallel file processing
* Efficient AST parsing
* Configurable file size limits
* Exclusion patterns for large projects

## Troubleshooting

### Common Issues

1. No vulnerabilities found in obviously vulnerable code

- Check that the file has a .py extension
- Verify the detector is enabled in configuration
- Ensure the code pattern matches detector rules

2. Scanner is slow on large projects

- Use exclusion patterns to skip unnecessary directories
- Increase file size limit if needed
- Consider running on a subset of files

3. False positives

- Review detector configuration
- Consider creating custom detectors for your use case
- Report false positives to improve the tool

## Support

* Documentation: ReadTheDocs
* Issues: GitHub Issues
* Discussions: GitHub Discussions

## License

This project is licensed under the MIT License - see the LICENSE file for details.