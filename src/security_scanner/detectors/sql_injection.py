import ast
from typing import List, Dict, Any


class SQLInjectionDetector:
    """Detect SQL injection vulnerabilities."""
    
    def analyze(self, node: ast.AST, file_path: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        if isinstance(node, ast.Call):
            vulnerabilities.extend(self._check_sql_calls(node, file_path))
        
        return vulnerabilities
    
    def _check_sql_calls(self, node: ast.Call, file_path: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        # Check for cursor.execute with string formatting
        if (isinstance(node.func, ast.Attribute) and 
            node.func.attr in ['execute', 'executemany']):
            
            if node.args and self._has_string_formatting(node.args[0]):
                vulnerabilities.append({
                    'type': 'SQL Injection',
                    'severity': 'High',
                    'file_path': file_path,
                    'line_number': node.lineno,
                    'description': 'Potential SQL injection vulnerability using string formatting in SQL query',
                    'code_snippet': self._get_node_code(node),
                    'recommendation': 'Use parameterized queries with placeholders (?) instead of string formatting'
                })
        
        return vulnerabilities
    
    def _has_string_formatting(self, node: ast.AST) -> bool:
        """Check if node contains unsafe string formatting."""
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            return True  # % formatting
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == 'format':
                return True  # .format() method
        elif isinstance(node, ast.JoinedStr):
            return True  # f-string
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return True  # String concatenation
            
        return False
    
    def _get_node_code(self, node: ast.AST) -> str:
        """Extract code snippet from node (simplified)."""
        if hasattr(node, 'lineno'):
            return f"Line {node.lineno}: SQL execution with potential injection"
        return "SQL execution with potential injection"