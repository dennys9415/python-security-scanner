#!/usr/bin/env python3
"""
Basic example of using the Python Security Scanner.
"""

import os
import sys

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.security_scanner import SecurityScanner


def main():
    """Demonstrate basic scanner usage."""
    scanner = SecurityScanner()
    
    # Scan the current directory
    target = "."
    
    print(f"Scanning {os.path.abspath(target)} for security vulnerabilities...")
    
    try:
        vulnerabilities = scanner.scan(target)
        
        print(f"\nScan completed. Found {len(vulnerabilities)} vulnerabilities.")
        
        # Generate reports
        if vulnerabilities:
            scanner.generate_report(vulnerabilities, "security_report.json", "json")
            scanner.generate_report(vulnerabilities, "security_report.html", "html")
            print("Reports generated: security_report.json, security_report.html")
        else:
            print("No vulnerabilities found!")
            
    except Exception as e:
        print(f"Error during scanning: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()