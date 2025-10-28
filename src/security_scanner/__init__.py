"""
Python Security Scanner - A professional security vulnerability scanner.
"""

__version__ = "1.0.0"
__author__ = "Your Name"
__email__ = "your.email@example.com"

from .core.scanner import SecurityScanner
from .cli import main

__all__ = ["SecurityScanner", "main"]