#!/usr/bin/env python3
"""
Advanced example of using the Python Security Scanner with custom configuration
and multiple scan strategies.
"""

import os
import sys
import json
import yaml
from datetime import datetime
from pathlib import Path

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.security_scanner import SecurityScanner
from src.security_scanner.detectors.hardcoded_secrets import HardcodedSecretsDetector


class AdvancedSecurityScanner:
    """Advanced scanner with custom configuration and reporting."""
    
    def __init__(self, config_path=None):
        self.config = self._load_config(config_path)
        self.scanner = SecurityScanner(self.config)
        self.setup_custom_detectors()
    
    def _load_config(self, config_path):
        """Load configuration from YAML file or use defaults."""
        default_config = {
            'scan': {
                'exclude_dirs': ['.git', '__pycache__', 'venv', '.env', 'node_modules'],
                'max_file_size': 10485760,  # 10MB
                'follow_symlinks': False,
                'file_extensions': ['.py']
            },
            'detectors': {
                'sql_injection': {'enabled': True},
                'xss': {'enabled': True},
                'command_injection': {'enabled': True},
                'file_inclusion': {'enabled': True},
                'hardcoded_secrets': {'enabled': True, 'custom_patterns': []},
                'insecure_deserialization': {'enabled': True}
            },
            'reporting': {
                'min_severity': 'Low',
                'include_code_snippets': True,
                'output_dir': 'security_reports'
            }
        }
        
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f)
                # Merge with default config
                self._merge_config(default_config, user_config)
        
        return default_config
    
    def _merge_config(self, default, user):
        """Recursively merge user config with defaults."""
        for key, value in user.items():
            if isinstance(value, dict) and key in default:
                self._merge_config(default[key], value)
            else:
                default[key] = value
    
    def setup_custom_detectors(self):
        """Setup custom detectors and configurations."""
        # Example: Add custom secret patterns
        secrets_detector = None
        for detector in self.scanner.detector.detectors:
            if isinstance(detector, HardcodedSecretsDetector):
                secrets_detector = detector
                break
        
        if secrets_detector and 'custom_patterns' in self.config['detectors']['hardcoded_secrets']:
            for pattern in self.config['detectors']['hardcoded_secrets']['custom_patterns']:
                secrets_detector.secret_patterns[pattern['name']] = pattern['regex']
    
    def scan_project(self, project_path):
        """Perform comprehensive security scan."""
        print(f"🔍 Starting advanced security scan of: {project_path}")
        print(f"📁 Configuration: {len(self.config['detectors'])} detectors enabled")
        
        # Create output directory
        output_dir = self.config['reporting']['output_dir']
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        try:
            # Perform scan
            vulnerabilities = self.scanner.scan(project_path)
            
            # Generate reports
            self._generate_comprehensive_reports(vulnerabilities, output_dir, timestamp)
            
            # Generate summary
            self._generate_scan_summary(vulnerabilities, output_dir, timestamp)
            
            return vulnerabilities
            
        except Exception as e:
            print(f"❌ Scan failed: {e}")
            raise
    
    def _generate_comprehensive_reports(self, vulnerabilities, output_dir, timestamp):
        """Generate multiple report formats."""
        base_name = f"security_scan_{timestamp}"
        
        # JSON report (machine-readable)
        json_report = os.path.join(output_dir, f"{base_name}.json")
        self.scanner.generate_report(vulnerabilities, json_report, 'json')
        print(f"📊 JSON report: {json_report}")
        
        # HTML report (human-readable)
        html_report = os.path.join(output_dir, f"{base_name}.html")
        self.scanner.generate_report(vulnerabilities, html_report, 'html')
        print(f"📄 HTML report: {html_report}")
        
        # Console report (immediate feedback)
        print("\n" + "="*60)
        print("🚨 SECURITY SCAN RESULTS")
        print("="*60)
        self.scanner.generate_report(vulnerabilities, '', 'console')
    
    def _generate_scan_summary(self, vulnerabilities, output_dir, timestamp):
        """Generate a detailed scan summary."""
        summary = {
            'scan_metadata': {
                'timestamp': timestamp,
                'scanner_version': '1.0.0',
                'total_files_scanned': 'N/A',  # Would need to be tracked in scanner
                'scan_duration': 'N/A'  # Would need timing implementation
            },
            'vulnerability_summary': {
                'total': len(vulnerabilities),
                'by_severity': self._count_by_severity(vulnerabilities),
                'by_type': self._count_by_type(vulnerabilities)
            },
            'recommendations': self._generate_recommendations(vulnerabilities)
        }
        
        summary_path = os.path.join(output_dir, f"scan_summary_{timestamp}.json")
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"📋 Scan summary: {summary_path}")
    
    def _count_by_severity(self, vulnerabilities):
        """Count vulnerabilities by severity level."""
        counts = {}
        for vuln in vulnerabilities:
            severity = vuln['severity']
            counts[severity] = counts.get(severity, 0) + 1
        return counts
    
    def _count_by_type(self, vulnerabilities):
        """Count vulnerabilities by type."""
        counts = {}
        for vuln in vulnerabilities:
            vuln_type = vuln['type']
            counts[vuln_type] = counts.get(vuln_type, 0) + 1
        return counts
    
    def _generate_recommendations(self, vulnerabilities):
        """Generate actionable recommendations based on findings."""
        recommendations = []
        
        critical_vulns = [v for v in vulnerabilities if v['severity'] == 'Critical']
        high_vulns = [v for v in vulnerabilities if v['severity'] == 'High']
        
        if critical_vulns:
            recommendations.append({
                'priority': 'CRITICAL',
                'action': 'Immediately address critical vulnerabilities',
                'details': f'Found {len(critical_vulns)} critical security issues that require immediate attention'
            })
        
        if high_vulns:
            recommendations.append({
                'priority': 'HIGH',
                'action': 'Address high-severity vulnerabilities',
                'details': f'Found {len(high_vulns)} high-severity security issues'
            })
        
        # Technology-specific recommendations
        vuln_types = {v['type'] for v in vulnerabilities}
        
        if 'SQL Injection' in vuln_types:
            recommendations.append({
                'priority': 'HIGH',
                'action': 'Implement parameterized queries',
                'details': 'Replace string formatting in SQL queries with parameterized statements'
            })
        
        if 'Command Injection' in vuln_types:
            recommendations.append({
                'priority': 'CRITICAL',
                'action': 'Use subprocess with shell=False',
                'details': 'Replace os.system and subprocess with shell=True with safe alternatives'
            })
        
        if 'Hardcoded Secret' in vuln_types:
            recommendations.append({
                'priority': 'HIGH',
                'action': 'Move secrets to environment variables',
                'details': 'Remove hardcoded credentials and use environment variables or secret management'
            })
        
        if not vulnerabilities:
            recommendations.append({
                'priority': 'INFO',
                'action': 'Maintain security practices',
                'details': 'No vulnerabilities found. Continue following secure coding practices.'
            })
        
        return recommendations


def create_sample_config():
    """Create a sample configuration file."""
    sample_config = {
        'scan': {
            'exclude_dirs': ['.git', '__pycache__', 'venv', '.env', 'node_modules', 'dist'],
            'max_file_size': 5242880,  # 5MB
            'follow_symlinks': False,
            'file_extensions': ['.py', '.pyw']
        },
        'detectors': {
            'sql_injection': {'enabled': True},
            'xss': {'enabled': True},
            'command_injection': {'enabled': True},
            'file_inclusion': {'enabled': True},
            'hardcoded_secrets': {
                'enabled': True,
                'custom_patterns': [
                    {
                        'name': 'custom_api_key',
                        'regex': 'CUSTOM_API_KEY\\s*=\\s*[\'\"][^\'\"]+[\'\"]'
                    }
                ]
            },
            'insecure_deserialization': {'enabled': True}
        },
        'reporting': {
            'min_severity': 'Medium',
            'include_code_snippets': True,
            'output_dir': 'security_reports'
        }
    }
    
    with open('advanced_config.yaml', 'w') as f:
        yaml.dump(sample_config, f, default_flow_style=False)
    
    print("📝 Sample configuration created: advanced_config.yaml")


def main():
    """Main function demonstrating advanced scanner usage."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Advanced Security Scanner')
    parser.add_argument('target', help='Directory or file to scan')
    parser.add_argument('--config', '-c', help='Configuration file path')
    parser.add_argument('--create-config', action='store_true', 
                       help='Create a sample configuration file')
    
    args = parser.parse_args()
    
    if args.create_config:
        create_sample_config()
        return
    
    if not os.path.exists(args.target):
        print(f"❌ Error: Target '{args.target}' does not exist")
        return 1
    
    try:
        # Initialize advanced scanner
        advanced_scanner = AdvancedSecurityScanner(args.config)
        
        # Perform scan
        vulnerabilities = advanced_scanner.scan_project(args.target)
        
        print(f"\n✅ Scan completed! Found {len(vulnerabilities)} vulnerabilities")
        
        # Exit with appropriate code for CI/CD integration
        if vulnerabilities:
            critical_count = len([v for v in vulnerabilities if v['severity'] == 'Critical'])
            if critical_count > 0:
                print(f"🚨 Found {critical_count} CRITICAL vulnerabilities - failing build")
                return 1
            else:
                print("⚠️  Vulnerabilities found but no critical issues")
                return 0
        else:
            print("🎉 No vulnerabilities found!")
            return 0
            
    except Exception as e:
        print(f"💥 Fatal error: {e}")
        return 1


if __name__ == "__main__":
    exit(main())