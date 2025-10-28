#!/usr/bin/env python3
"""
Example of creating a custom vulnerability detector.
"""

import ast
from typing import List, Dict, Any
from src.security_scanner.core.vulnerability_detector import VulnerabilityDetector


class CustomDetector:
    """Example custom detector for finding print statements (for demonstration)."""
    
    def analyze(self, node: ast.AST, file_path: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == 'print':
                vulnerabilities.append({
                    'type': 'Debug Statement',
                    'severity': 'Low',
                    'file_path': file_path,
                    'line_number': node.lineno,
                    'description': 'Print statement found in code',
                    'code_snippet': 'Consider removing debug print statements in production',
                    'recommendation': 'Use logging instead of print statements'
                })
        
        return vulnerabilities


def main():
    """Example of using custom detector."""
    # Create scanner with custom detector
    scanner = SecurityScanner()
    
    # Add custom detector
    custom_detector = CustomDetector()
    scanner.detector.detectors.append(custom_detector)
    
    # Scan with custom detector
    code = """
print("Hello world")
x = 1 + 1
print(f"Result: {x}")
"""
    
    # For this example, we'll create a temporary file
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_file = f.name
    
    try:
        vulnerabilities = scanner.scan(temp_file)
        
        print(f"Found {len(vulnerabilities)} vulnerabilities:")
        for vuln in vulnerabilities:
            print(f"  - {vuln['type']} at line {vuln['line_number']}")
            
    finally:
        import os
        os.unlink(temp_file)


if __name__ == "__main__":
    main()