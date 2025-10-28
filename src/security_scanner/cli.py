#!/usr/bin/env python3
"""
Command Line Interface for Python Security Scanner.
"""

import click
import json
import yaml
import sys
from pathlib import Path
from typing import Optional

from .core.scanner import SecurityScanner
from .utils.logger import setup_logger


@click.group()
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--config', '-c', type=click.Path(exists=True), help='Configuration file path')
@click.version_option(version='1.0.0', prog_name='Python Security Scanner')
@click.pass_context
def cli(ctx, verbose, config):
    """Python Security Scanner - Professional vulnerability detection tool."""
    ctx.ensure_object(dict)
    ctx.obj['VERBOSE'] = verbose
    ctx.obj['CONFIG'] = config
    
    # Setup logger
    setup_logger(verbose=verbose)
    
    # Load configuration if provided
    if config:
        try:
            with open(config, 'r') as f:
                user_config = yaml.safe_load(f)
                ctx.obj['USER_CONFIG'] = user_config
        except Exception as e:
            click.echo(f"Error loading configuration: {e}", err=True)
            sys.exit(1)


@cli.command()
@click.argument('target', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output file for report')
@click.option('--format', '-f', type=click.Choice(['html', 'json', 'console']), 
              default='console', help='Report format')
@click.option('--detectors', '-d', help='Comma-separated list of detectors to use')
@click.option('--min-severity', type=click.Choice(['Low', 'Medium', 'High', 'Critical']),
              default='Low', help='Minimum severity level to report')
@click.option('--fail-on', type=click.Choice(['Never', 'Critical', 'High', 'Medium', 'Any']),
              default='Never', help='Exit with error code if vulnerabilities found')
@click.pass_context
def scan(ctx, target, output, format, detectors, min_severity, fail_on):
    """Scan a target for security vulnerabilities."""
    logger = setup_logger(verbose=ctx.obj['VERBOSE'])
    
    try:
        # Load configuration
        config = ctx.obj.get('USER_CONFIG', {})
        
        # Initialize scanner
        scanner = SecurityScanner(config)
        
        # Filter detectors if specified
        if detectors:
            detector_list = [d.strip() for d in detectors.split(',')]
            scanner.detector.detectors = [
                detector for detector in scanner.detector.detectors
                if detector.__class__.__name__.replace('Detector', '').lower() in detector_list
            ]
            if not scanner.detector.detectors:
                click.echo(f"Error: No valid detectors found from: {detectors}", err=True)
                sys.exit(1)
        
        click.echo(f"🔍 Scanning {target} for security vulnerabilities...")
        click.echo(f"📊 Using {len(scanner.detector.detectors)} detectors")
        
        # Perform scan
        vulnerabilities = scanner.scan(target)
        
        # Filter by severity
        severity_levels = ['Critical', 'High', 'Medium', 'Low']
        min_severity_index = severity_levels.index(min_severity)
        filtered_vulnerabilities = [
            v for v in vulnerabilities
            if severity_levels.index(v['severity']) >= min_severity_index
        ]
        
        # Generate report
        if output:
            scanner.generate_report(filtered_vulnerabilities, output, format)
            click.echo(f"📄 Report generated: {output}")
        else:
            # Print to console
            scanner.generate_report(filtered_vulnerabilities, '', 'console')
        
        # Show summary
        severity_counts = {}
        for severity in severity_levels:
            count = len([v for v in filtered_vulnerabilities if v['severity'] == severity])
            if count > 0:
                severity_counts[severity] = count
        
        click.echo("\n" + "="*50)
        click.echo("📋 SCAN SUMMARY")
        click.echo("="*50)
        click.echo(f"Total vulnerabilities found: {len(filtered_vulnerabilities)}")
        
        for severity, count in severity_counts.items():
            color = {
                'Critical': 'red',
                'High': 'yellow', 
                'Medium': 'blue',
                'Low': 'green'
            }.get(severity, 'white')
            click.echo(click.style(f"  {severity}: {count}", fg=color))
        
        # Exit with appropriate code based on fail-on setting
        if fail_on != 'Never':
            if fail_on == 'Any' and filtered_vulnerabilities:
                sys.exit(1)
            elif fail_on == 'Critical' and severity_counts.get('Critical', 0) > 0:
                sys.exit(1)
            elif fail_on == 'High' and (severity_counts.get('Critical', 0) > 0 or 
                                      severity_counts.get('High', 0) > 0):
                sys.exit(1)
            elif fail_on == 'Medium' and (severity_counts.get('Critical', 0) > 0 or 
                                        severity_counts.get('High', 0) > 0 or
                                        severity_counts.get('Medium', 0) > 0):
                sys.exit(1)
        
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@cli.command()
def detectors():
    """List available vulnerability detectors."""
    scanner = SecurityScanner()
    available_detectors = scanner.detector.get_available_detectors()
    
    click.echo("🔧 Available vulnerability detectors:")
    click.echo("")
    
    detector_info = {
        'SQLInjectionDetector': {
            'name': 'SQL Injection',
            'description': 'Detects unsafe SQL query construction',
            'severity': 'High'
        },
        'XSSDetector': {
            'name': 'Cross-Site Scripting (XSS)',
            'description': 'Detects unsafe template rendering',
            'severity': 'High'
        },
        'CommandInjectionDetector': {
            'name': 'Command Injection',
            'description': 'Detects unsafe command execution',
            'severity': 'Critical'
        },
        'FileInclusionDetector': {
            'name': 'File Inclusion',
            'description': 'Detects unsafe file operations',
            'severity': 'Medium'
        },
        'HardcodedSecretsDetector': {
            'name': 'Hardcoded Secrets',
            'description': 'Detects passwords and API keys in code',
            'severity': 'High'
        },
        'InsecureDeserializationDetector': {
            'name': 'Insecure Deserialization',
            'description': 'Detects unsafe deserialization',
            'severity': 'High'
        }
    }
    
    for detector in available_detectors:
        info = detector_info.get(detector, {
            'name': detector.replace('Detector', ''),
            'description': 'No description available',
            'severity': 'Unknown'
        })
        
        severity_color = {
            'Critical': 'red',
            'High': 'yellow',
            'Medium': 'blue',
            'Low': 'green',
            'Unknown': 'white'
        }.get(info['severity'], 'white')
        
        click.echo(click.style(f"  • {info['name']} ", fg=severity_color) + 
                  click.style(f"({info['severity']})", fg=severity_color, bold=True))
        click.echo(f"    {info['description']}")
        click.echo("")


@cli.command()
@click.option('--output', '-o', type=click.Path(), 
              default='security-config.yaml', help='Output config file path')
@click.pass_context
def init(ctx, output):
    """Generate a default configuration file."""
    default_config = {
        'scan': {
            'exclude_dirs': ['.git', '__pycache__', 'venv', '.env', 'node_modules'],
            'max_file_size': 10485760,
            'follow_symlinks': False,
            'file_extensions': ['.py']
        },
        'detectors': {
            'sql_injection': {'enabled': True},
            'xss': {'enabled': True},
            'command_injection': {'enabled': True},
            'file_inclusion': {'enabled': True},
            'hardcoded_secrets': {'enabled': True},
            'insecure_deserialization': {'enabled': True}
        },
        'reporting': {
            'min_severity': 'Low',
            'include_code_snippets': True,
            'output_formats': ['console', 'html', 'json']
        }
    }
    
    try:
        with open(output, 'w') as f:
            yaml.dump(default_config, f, default_flow_style=False, indent=2)
        
        click.echo(f"✅ Configuration file created: {output}")
        click.echo("")
        click.echo("You can now:")
        click.echo("  1. Edit the configuration file to customize scanning")
        click.echo("  2. Run scans using: security-scanner scan <target> --config config.yaml")
        
    except Exception as e:
        click.echo(f"❌ Error creating configuration file: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('config_file', type=click.Path(exists=True))
def validate(config_file):
    """Validate a configuration file."""
    try:
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
        
        # Basic validation
        required_sections = ['scan', 'detectors', 'reporting']
        for section in required_sections:
            if section not in config:
                click.echo(f"❌ Missing required section: {section}", err=True)
                sys.exit(1)
        
        # Validate detectors
        valid_detectors = [
            'sql_injection', 'xss', 'command_injection', 
            'file_inclusion', 'hardcoded_secrets', 'insecure_deserialization'
        ]
        
        for detector_name, detector_config in config['detectors'].items():
            if detector_name not in valid_detectors:
                click.echo(f"⚠️  Unknown detector: {detector_name}")
        
        click.echo("✅ Configuration file is valid")
        
    except yaml.YAMLError as e:
        click.echo(f"❌ Invalid YAML: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Error validating configuration: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--format', '-f', type=click.Choice(['json', 'yaml']), 
              default='yaml', help='Output format')
def schema(format):
    """Show configuration schema."""
    schema = {
        'scan': {
            'exclude_dirs': {
                'type': 'list',
                'description': 'Directories to exclude from scanning',
                'default': ['.git', '__pycache__', 'venv', '.env']
            },
            'max_file_size': {
                'type': 'integer',
                'description': 'Maximum file size to scan (in bytes)',
                'default': 10485760
            },
            'follow_symlinks': {
                'type': 'boolean',
                'description': 'Whether to follow symbolic links',
                'default': False
            }
        },
        'detectors': {
            'sql_injection': {
                'enabled': {
                    'type': 'boolean',
                    'description': 'Enable SQL injection detection',
                    'default': True
                }
            },
            # ... other detectors
        },
        'reporting': {
            'min_severity': {
                'type': 'string',
                'description': 'Minimum severity level to report',
                'default': 'Low',
                'allowed': ['Low', 'Medium', 'High', 'Critical']
            },
            'include_code_snippets': {
                'type': 'boolean',
                'description': 'Include code snippets in reports',
                'default': True
            }
        }
    }
    
    if format == 'json':
        click.echo(json.dumps(schema, indent=2))
    else:
        click.echo(yaml.dump(schema, default_flow_style=False))


def main():
    """Main entry point for the CLI."""
    try:
        cli(obj={})
    except KeyboardInterrupt:
        click.echo("\n⚠️  Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        click.echo(f"💥 Unexpected error: {e}", err=True)
        sys.exit(1)


if __name__ == '__main__':
    main()