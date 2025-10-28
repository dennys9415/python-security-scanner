import ast
from typing import List, Dict, Any


class XSSDetector:
    """Detect Cross-Site Scripting (XSS) vulnerabilities."""
    
    def analyze(self, node: ast.AST, file_path: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        if isinstance(node, ast.Call):
            vulnerabilities.extend(self._check_unsafe_html_rendering(node, file_path))
        elif isinstance(node, ast.Expr):
            vulnerabilities.extend(self._check_direct_output(node, file_path))
        
        return vulnerabilities
    
    def _check_unsafe_html_rendering(self, node: ast.Call, file_path: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        # Check for Flask/Jinja2 rendering with user input
        if (isinstance(node.func, ast.Attribute) and 
            node.func.attr in ['render_template', 'render_template_string']):
            
            if node.args and self._has_user_input(node.args[0]):
                vulnerabilities.append({
                    'type': 'Cross-Site Scripting (XSS)',
                    'severity': 'High',
                    'file_path': file_path,
                    'line_number': node.lineno,
                    'description': 'Potential XSS vulnerability in template rendering with user input',
                    'code_snippet': self._get_node_code(node),
                    'recommendation': 'Always escape user input before rendering in templates'
                })
        
        return vulnerabilities
    
    def _check_direct_output(self, node: ast.Expr, file_path: str) -> List[Dict[str, Any]]:
        # This is a simplified check - real implementation would be more complex
        return []
    
    def _has_user_input(self, node: ast.AST) -> bool:
        """Check if node might contain user input (simplified)."""
        # In a real implementation, this would track variable sources
        return True
    
    def _get_node_code(self, node: ast.AST) -> str:
        if hasattr(node, 'lineno'):
            return f"Line {node.lineno}: Potential XSS in template rendering"
        return "Potential XSS vulnerability"