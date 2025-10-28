import ast
from typing import List, Dict, Any


class FileInclusionDetector:
    """Detect file inclusion vulnerabilities."""
    
    def analyze(self, node: ast.AST, file_path: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        if isinstance(node, ast.Call):
            vulnerabilities.extend(self._check_file_operations(node, file_path))
        elif isinstance(node, ast.With):
            vulnerabilities.extend(self._check_with_statements(node, file_path))
        
        return vulnerabilities
    
    def _check_file_operations(self, node: ast.Call, file_path: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        file_functions = ['open', 'file']
        unsafe_modes = ['w', 'a', 'r+', 'w+', 'a+']
        
        if (isinstance(node.func, ast.Name) and
            node.func.id in file_functions):
            
            if node.args and self._has_user_input(node.args[0]):
                mode = self._get_file_mode(node)
                if mode in unsafe_modes:
                    vulnerabilities.append({
                        'type': 'Unsafe File Operation',
                        'severity': 'Medium',
                        'file_path': file_path,
                        'line_number': node.lineno,
                        'description': f'File operation with user-controlled path in mode "{mode}"',
                        'code_snippet': self._get_node_code(node),
                        'recommendation': 'Validate and sanitize file paths, avoid user-controlled paths for write operations'
                    })
        
        return vulnerabilities
    
    def _get_file_mode(self, node: ast.Call) -> str:
        """Extract file mode from open() call."""
        if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
            return node.args[1].value
        return 'r'  # default mode
    
    def _has_user_input(self, node: ast.AST) -> bool:
        return True  # Simplified
    
    def _get_node_code(self, node: ast.AST) -> str:
        if hasattr(node, 'lineno'):
            return f"Line {node.lineno}: Potential file inclusion vulnerability"
        return "Potential file inclusion vulnerability"