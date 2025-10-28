import json
import os
from datetime import datetime
from typing import List, Dict, Any
from ..utils.logger import setup_logger


class ReportGenerator:
    """Generates vulnerability reports in multiple formats."""
    
    def __init__(self):
        self.logger = setup_logger()
    
    def generate(self, vulnerabilities: List[Dict[str, Any]], 
                output_path: str, format: str = 'console') -> None:
        """Generate report in specified format."""
        if format == 'json':
            self._generate_json(vulnerabilities, output_path)
        elif format == 'html':
            self._generate_html(vulnerabilities, output_path)
        elif format == 'console':
            self._generate_console(vulnerabilities)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _generate_json(self, vulnerabilities: List[Dict[str, Any]], output_path: str) -> None:
        """Generate JSON report."""
        report = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "scanner_version": "1.0.0",
                "total_vulnerabilities": len(vulnerabilities)
            },
            "vulnerabilities": vulnerabilities
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
    
    def _generate_html(self, vulnerabilities: List[Dict[str, Any]], output_path: str) -> None:
        """Generate HTML report."""
        severity_colors = {
            "Critical": "#ff4444",
            "High": "#ff8800", 
            "Medium": "#ffcc00",
            "Low": "#44ff44"
        }
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
                .vulnerability {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
                .critical {{ border-left: 5px solid {severity_colors['Critical']}; }}
                .high {{ border-left: 5px solid {severity_colors['High']}; }}
                .medium {{ border-left: 5px solid {severity_colors['Medium']}; }}
                .low {{ border-left: 5px solid {severity_colors['Low']}; }}
                .severity {{ font-weight: bold; padding: 2px 8px; border-radius: 3px; color: white; }}
                .code {{ background: #f8f9fa; padding: 10px; border-radius: 3px; font-family: monospace; }}
                .summary {{ background: #e9ecef; padding: 15px; border-radius: 5px; margin: 20px 0; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Security Scan Report</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>Total Vulnerabilities: {len(vulnerabilities)}</p>
            </div>
            
            <div class="summary">
                <h3>Summary</h3>
                <p>Critical: {len([v for v in vulnerabilities if v['severity'] == 'Critical'])}</p>
                <p>High: {len([v for v in vulnerabilities if v['severity'] == 'High'])}</p>
                <p>Medium: {len([v for v in vulnerabilities if v['severity'] == 'Medium'])}</p>
                <p>Low: {len([v for v in vulnerabilities if v['severity'] == 'Low'])}</p>
            </div>
        """
        
        for i, vuln in enumerate(vulnerabilities, 1):
            html_content += f"""
            <div class="vulnerability {vuln['severity'].lower()}">
                <h3>{i}. {vuln['type']}</h3>
                <p><strong>File:</strong> {vuln['file_path']} (Line {vuln['line_number']})</p>
                <p><strong>Severity:</strong> <span class="severity" style="background: {severity_colors.get(vuln['severity'], '#666')}">{vuln['severity']}</span></p>
                <p><strong>Description:</strong> {vuln['description']}</p>
                <p><strong>Recommendation:</strong> {vuln.get('recommendation', 'No specific recommendation')}</p>
                <div class="code">{vuln.get('code_snippet', 'No code snippet available')}</div>
            </div>
            """
        
        html_content += """
        </body>
        </html>
        """
        
        with open(output_path, 'w') as f:
            f.write(html_content)
    
    def _generate_console(self, vulnerabilities: List[Dict[str, Any]]) -> None:
        """Print report to console."""
        from colorama import Fore, Style, init
        init()  # Initialize colorama
        
        severity_colors = {
            "Critical": Fore.RED,
            "High": Fore.YELLOW,
            "Medium": Fore.BLUE,
            "Low": Fore.GREEN
        }
        
        print(f"\n{Fore.CYAN}=== Security Scan Results ==={Style.RESET_ALL}")
        print(f"Total vulnerabilities found: {len(vulnerabilities)}")
        
        for i, vuln in enumerate(vulnerabilities, 1):
            color = severity_colors.get(vuln['severity'], Fore.WHITE)
            print(f"\n{color}--- Vulnerability {i}: {vuln['type']} ---{Style.RESET_ALL}")
            print(f"File: {vuln['file_path']}:{vuln['line_number']}")
            print(f"Severity: {color}{vuln['severity']}{Style.RESET_ALL}")
            print(f"Description: {vuln['description']}")
            if 'recommendation' in vuln:
                print(f"Recommendation: {vuln['recommendation']}")
            if 'code_snippet' in vuln:
                print(f"Code: {vuln['code_snippet']}")