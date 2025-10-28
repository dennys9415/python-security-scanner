import ast
from typing import List, Dict, Any


class InsecureDeserializationDetector:
    """Detect insecure deserialization vulnerabilities."""
    
    def analyze(self, node: ast.AST, file_path: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        if isinstance(node, ast.Call):
            vulnerabilities.extend(self._check_pickle_calls(node, file_path))
            vulnerabilities.extend(self._check_yaml_calls(node, file_path))
        
        return vulnerabilities
    
    def _check_pickle_calls(self, node: ast.Call, file_path: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        if (isinstance(node.func, ast.Attribute) and
            node.func.attr in ['loads', 'load']):
            
            if (isinstance(node.func.value, ast.Name) and
                node.func.value.id == 'pickle'):
                
                vulnerabilities.append({
                    'type': 'Insecure Deserialization',
                    'severity': 'High',
                    'file_path': file_path,
                    'line_number': node.lineno,
                    'description': 'Unsafe deserialization using pickle',
                    'code_snippet': self._get_node_code(node),
                    'recommendation': 'Avoid pickle for untrusted data. Use JSON or other safe formats with validation'
                })
        
        return vulnerabilities
    
    def _check_yaml_calls(self, node: ast.Call, file_path: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        if (isinstance(node.func, ast.Attribute) and
            node.func.attr == 'load'):
            
            if (isinstance(node.func.value, ast.Name) and
                node.func.value.id in ['yaml', 'YAML']):
                
                vulnerabilities.append({
                    'type': 'Insecure Deserialization',
                    'severity': 'Medium',
                    'file_path': file_path,
                    'line_number': node.lineno,
                    'description': 'Potential unsafe YAML deserialization',
                    'code_snippet': self._get_node_code(node),
                    'recommendation': 'Use yaml.safe_load() instead of yaml.load() for untrusted data'
                })
        
        return vulnerabilities
    
    def _get_node_code(self, node: ast.AST) -> str:
        if hasattr(node, 'lineno'):
            return f"Line {node.lineno}: Potential insecure deserialization"
        return "Potential insecure deserialization"