import ast
from typing import List, Dict, Any


class CommandInjectionDetector:
    """Detect command injection vulnerabilities."""
    
    def analyze(self, node: ast.AST, file_path: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        if isinstance(node, ast.Call):
            vulnerabilities.extend(self._check_os_calls(node, file_path))
            vulnerabilities.extend(self._check_subprocess_calls(node, file_path))
        
        return vulnerabilities
    
    def _check_os_calls(self, node: ast.Call, file_path: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        os_commands = ['system', 'popen', 'popen2', 'popen3', 'popen4']
        
        if (isinstance(node.func, ast.Attribute) and 
            isinstance(node.func.value, ast.Name) and
            node.func.value.id == 'os' and
            node.func.attr in os_commands):
            
            if node.args and self._has_user_input(node.args[0]):
                vulnerabilities.append({
                    'type': 'Command Injection',
                    'severity': 'Critical',
                    'file_path': file_path,
                    'line_number': node.lineno,
                    'description': f'Potential command injection in os.{node.func.attr}',
                    'code_snippet': self._get_node_code(node),
                    'recommendation': 'Use subprocess with shell=False and validate/sanitize all inputs'
                })
        
        return vulnerabilities
    
    def _check_subprocess_calls(self, node: ast.Call, file_path: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        if (isinstance(node.func, ast.Attribute) and
            isinstance(node.func.value, ast.Name) and
            node.func.value.id == 'subprocess' and
            node.func.attr in ['call', 'run', 'Popen']):
            
            # Check for shell=True with user input
            if self._has_shell_true(node) and self._has_user_input_in_args(node):
                vulnerabilities.append({
                    'type': 'Command Injection',
                    'severity': 'Critical',
                    'file_path': file_path,
                    'line_number': node.lineno,
                    'description': f'Potential command injection in subprocess.{node.func.attr} with shell=True',
                    'code_snippet': self._get_node_code(node),
                    'recommendation': 'Avoid shell=True, use list arguments instead of strings'
                })
        
        return vulnerabilities
    
    def _has_shell_true(self, node: ast.Call) -> bool:
        """Check if shell=True is used."""
        for keyword in node.keywords:
            if keyword.arg == 'shell' and isinstance(keyword.value, ast.Constant):
                if keyword.value.value is True:
                    return True
        return False
    
    def _has_user_input_in_args(self, node: ast.Call) -> bool:
        """Check if arguments might contain user input."""
        return bool(node.args)
    
    def _has_user_input(self, node: ast.AST) -> bool:
        return True  # Simplified
    
    def _get_node_code(self, node: ast.AST) -> str:
        if hasattr(node, 'lineno'):
            return f"Line {node.lineno}: Potential command injection"
        return "Potential command injection"