# Contributing Guide

## Development Setup

1. Fork the repository
2. Clone your fork
3. Install development dependencies:

```bash
pip install -e .[dev]
pre-commit install
```

## Adding New Detectors

1. Create a new detector class in src/security_scanner/detectors/
2. Implement the analyze method
3. Add the detector to the __init__.py file
4. Add tests in tests/test_detectors.py

## Running Tests

```bash
pytest
```

## Code Style

We use:

* Black for code formatting
* isort for import sorting
* flake8 for linting
* mypy for type checking

Run all checks:

```bash
black src tests
isort src tests
flake8 src tests
mypy src
```

## Pull Request Process

1. Create a feature branch
2. Make your changes
3. Add tests
4. Ensure all checks pass
5. Submit a pull request