import ast
import re
from typing import List, Dict, Any


class HardcodedSecretsDetector:
    """Detect hardcoded secrets and credentials."""
    
    def __init__(self):
        self.secret_patterns = {
            'password': re.compile(r'password\s*=\s*[\'\"][^\'\"]+[\'\"]', re.IGNORECASE),
            'api_key': re.compile(r'api[_-]?key\s*=\s*[\'\"][^\'\"]+[\'\"]', re.IGNORECASE),
            'secret': re.compile(r'secret\s*=\s*[\'\"][^\'\"]+[\'\"]', re.IGNORECASE),
            'token': re.compile(r'token\s*=\s*[\'\"][^\'\"]+[\'\"]', re.IGNORECASE),
        }
    
    def analyze(self, node: ast.AST, file_path: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        if isinstance(node, ast.Assign):
            vulnerabilities.extend(self._check_assignment(node, file_path))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            vulnerabilities.extend(self._check_string_constant(node, file_path))
        
        return vulnerabilities
    
    def _check_assignment(self, node: ast.Assign, file_path: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        for target in node.targets:
            if isinstance(target, ast.Name):
                target_name = target.id.lower()
                
                # Check variable name for secret indicators
                if any(keyword in target_name for keyword in ['password', 'secret', 'key', 'token']):
                    if (isinstance(node.value, ast.Constant) and 
                        isinstance(node.value.value, str) and
                        len(node.value.value) > 8):  # Basic length check
                        
                        vulnerabilities.append({
                            'type': 'Hardcoded Secret',
                            'severity': 'High',
                            'file_path': file_path,
                            'line_number': node.lineno,
                            'description': f'Potential hardcoded secret in variable "{target.id}"',
                            'code_snippet': self._get_node_code(node),
                            'recommendation': 'Use environment variables or secure secret management instead of hardcoding'
                        })
        
        return vulnerabilities
    
    def _check_string_constant(self, node: ast.Constant, file_path: str) -> List[Dict[str, Any]]:
        # Check for common secret patterns in strings
        vulnerabilities = []
        value = node.value
        
        for secret_type, pattern in self.secret_patterns.items():
            if pattern.search(value):
                vulnerabilities.append({
                    'type': 'Hardcoded Secret',
                    'severity': 'High',
                    'file_path': file_path,
                    'line_number': node.lineno,
                    'description': f'Potential hardcoded {secret_type} found',
                    'code_snippet': f'String containing potential {secret_type}',
                    'recommendation': 'Remove hardcoded secrets and use secure storage'
                })
        
        return vulnerabilities
    
    def _get_node_code(self, node: ast.AST) -> str:
        if hasattr(node, 'lineno'):
            return f"Line {node.lineno}: Potential hardcoded secret"
        return "Potential hardcoded secret"