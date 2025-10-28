import ast
import os
from pathlib import Path
from typing import List, Dict, Any, Optional
from .vulnerability_detector import VulnerabilityDetector
from .report_generator import ReportGenerator
from ..utils.logger import setup_logger


class SecurityScanner:
    """Main security scanner class."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = setup_logger()
        self.detector = VulnerabilityDetector()
        self.report_generator = ReportGenerator()
        
    def scan(self, target: str) -> List[Dict[str, Any]]:
        """
        Scan a target for security vulnerabilities.
        
        Args:
            target: Path to file or directory to scan
            
        Returns:
            List of detected vulnerabilities
        """
        self.logger.info(f"Starting security scan for: {target}")
        
        if os.path.isfile(target):
            return self._scan_file(target)
        elif os.path.isdir(target):
            return self._scan_directory(target)
        else:
            raise ValueError(f"Target not found: {target}")
    
    def _scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan a single file for vulnerabilities."""
        if not file_path.endswith('.py'):
            return []
            
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content)
            return self.detector.analyze_ast(tree, file_path)
            
        except (SyntaxError, UnicodeDecodeError) as e:
            self.logger.warning(f"Could not parse {file_path}: {e}")
            return []
    
    def _scan_directory(self, directory: str) -> List[Dict[str, Any]]:
        """Recursively scan a directory for vulnerabilities."""
        vulnerabilities = []
        
        for root, dirs, files in os.walk(directory):
            # Skip virtual environments and hidden directories
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['venv', '__pycache__']]
            
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    vulnerabilities.extend(self._scan_file(file_path))
        
        return vulnerabilities
    
    def generate_report(self, vulnerabilities: List[Dict[str, Any]], 
                       output_path: str, format: str = 'html') -> None:
        """
        Generate a vulnerability report.
        
        Args:
            vulnerabilities: List of detected vulnerabilities
            output_path: Path to save the report
            format: Report format (html, json, console)
        """
        self.report_generator.generate(vulnerabilities, output_path, format)