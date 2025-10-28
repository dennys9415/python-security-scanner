import pytest
import tempfile
import os
import json
from pathlib import Path
from src.security_scanner.core.scanner import SecurityScanner


class TestSecurityScanner:
    """Test cases for SecurityScanner class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.scanner = SecurityScanner()
        self.test_dir = tempfile.mkdtemp()

    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_scan_nonexistent_target(self):
        """Test scanning a non-existent target raises ValueError."""
        with pytest.raises(ValueError, match="Target not found"):
            self.scanner.scan("/nonexistent/path/that/does/not/exist")

    def test_scan_python_file_with_sql_injection(self):
        """Test scanning a Python file with SQL injection vulnerability."""
        test_code = '''
import sqlite3

def unsafe_query(user_input):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    # This is unsafe - SQL injection vulnerability
    cursor.execute("SELECT * FROM users WHERE username = '%s'" % user_input)
    return cursor.fetchall()
'''
        test_file = os.path.join(self.test_dir, "unsafe_sql.py")
        with open(test_file, 'w') as f:
            f.write(test_code)

        vulnerabilities = self.scanner.scan(test_file)
        
        assert len(vulnerabilities) > 0
        sql_vulnerabilities = [v for v in vulnerabilities if v['type'] == 'SQL Injection']
        assert len(sql_vulnerabilities) > 0
        assert sql_vulnerabilities[0]['severity'] == 'High'

    def test_scan_python_file_with_command_injection(self):
        """Test scanning a Python file with command injection vulnerability."""
        test_code = '''
import os

def unsafe_command(user_input):
    # This is unsafe - command injection vulnerability
    os.system("echo " + user_input)
'''
        test_file = os.path.join(self.test_dir, "unsafe_command.py")
        with open(test_file, 'w') as f:
            f.write(test_code)

        vulnerabilities = self.scanner.scan(test_file)
        
        assert len(vulnerabilities) > 0
        cmd_vulnerabilities = [v for v in vulnerabilities if v['type'] == 'Command Injection']
        assert len(cmd_vulnerabilities) > 0
        assert cmd_vulnerabilities[0]['severity'] == 'Critical'

    def test_scan_python_file_with_hardcoded_secret(self):
        """Test scanning a Python file with hardcoded secret."""
        test_code = '''
# Hardcoded credentials
API_KEY = "sk-1234567890abcdef"
PASSWORD = "super_secret_password123"

def connect_to_service():
    return API_KEY, PASSWORD
'''
        test_file = os.path.join(self.test_dir, "secrets.py")
        with open(test_file, 'w') as f:
            f.write(test_code)

        vulnerabilities = self.scanner.scan(test_file)
        
        assert len(vulnerabilities) > 0
        secret_vulnerabilities = [v for v in vulnerabilities if v['type'] == 'Hardcoded Secret']
        assert len(secret_vulnerabilities) >= 2  # Should find both API_KEY and PASSWORD

    def test_scan_safe_python_file(self):
        """Test scanning a safe Python file returns no vulnerabilities."""
        test_code = '''
def safe_function():
    """This function contains no security vulnerabilities."""
    result = 2 + 2
    return result

class SafeClass:
    def __init__(self):
        self.data = []
    
    def process_data(self, data):
        return [x for x in data if x > 0]
'''
        test_file = os.path.join(self.test_dir, "safe_code.py")
        with open(test_file, 'w') as f:
            f.write(test_code)

        vulnerabilities = self.scanner.scan(test_file)
        assert len(vulnerabilities) == 0

    def test_scan_directory_with_mixed_files(self):
        """Test scanning a directory containing multiple Python files."""
        # Create safe file
        safe_file = os.path.join(self.test_dir, "safe.py")
        with open(safe_file, 'w') as f:
            f.write('def safe(): return True')
        
        # Create unsafe file
        unsafe_file = os.path.join(self.test_dir, "unsafe.py")
        with open(unsafe_file, 'w') as f:
            f.write('import os; os.system("echo " + user_input)')
        
        # Create non-Python file (should be ignored)
        non_python_file = os.path.join(self.test_dir, "README.txt")
        with open(non_python_file, 'w') as f:
            f.write('This is not Python code')
        
        vulnerabilities = self.scanner.scan(self.test_dir)
        
        # Should find vulnerabilities from unsafe.py but not safe.py or README.txt
        assert len(vulnerabilities) > 0
        assert any('unsafe.py' in v['file_path'] for v in vulnerabilities)

    def test_scan_skips_hidden_directories(self):
        """Test that hidden directories are skipped during scanning."""
        # Create hidden directory
        hidden_dir = os.path.join(self.test_dir, ".venv")
        os.makedirs(hidden_dir)
        
        # Create Python file in hidden directory
        hidden_file = os.path.join(hidden_dir, "hidden.py")
        with open(hidden_file, 'w') as f:
            f.write('import os; os.system("rm -rf /")')  # Very unsafe code
        
        vulnerabilities = self.scanner.scan(self.test_dir)
        
        # Should not scan files in hidden directories
        assert not any('.venv' in v['file_path'] for v in vulnerabilities)

    def test_generate_json_report(self):
        """Test generating a JSON report."""
        test_code = '''
import sqlite3
cursor.execute("SELECT * FROM users WHERE name = %s" % user_input)
'''
        test_file = os.path.join(self.test_dir, "test_vuln.py")
        with open(test_file, 'w') as f:
            f.write(test_code)

        vulnerabilities = self.scanner.scan(test_file)
        report_path = os.path.join(self.test_dir, "report.json")
        
        self.scanner.generate_report(vulnerabilities, report_path, 'json')
        
        assert os.path.exists(report_path)
        
        with open(report_path, 'r') as f:
            report_data = json.load(f)
        
        assert 'metadata' in report_data
        assert 'vulnerabilities' in report_data
        assert len(report_data['vulnerabilities']) == len(vulnerabilities)

    def test_generate_html_report(self):
        """Test generating an HTML report."""
        test_code = '''
import os
os.system(user_input)
'''
        test_file = os.path.join(self.test_dir, "test_vuln.py")
        with open(test_file, 'w') as f:
            f.write(test_code)

        vulnerabilities = self.scanner.scan(test_file)
        report_path = os.path.join(self.test_dir, "report.html")
        
        self.scanner.generate_report(vulnerabilities, report_path, 'html')
        
        assert os.path.exists(report_path)
        
        with open(report_path, 'r') as f:
            html_content = f.read()
        
        assert '<html>' in html_content
        assert 'Security Scan Report' in html_content
        assert 'Command Injection' in html_content

    def test_generate_console_report(self):
        """Test generating console output (no file)."""
        test_code = '''
password = "hardcoded123"
'''
        test_file = os.path.join(self.test_dir, "test_secret.py")
        with open(test_file, 'w') as f:
            f.write(test_code)

        vulnerabilities = self.scanner.scan(test_file)
        
        # This should not raise an exception
        self.scanner.generate_report(vulnerabilities, '', 'console')

    def test_scan_file_with_syntax_error(self):
        """Test scanning a file with syntax errors handles gracefully."""
        test_code = '''
def broken_function(
    missing_parenthesis
    
print("hello world"
'''
        test_file = os.path.join(self.test_dir, "syntax_error.py")
        with open(test_file, 'w') as f:
            f.write(test_code)

        # Should not raise an exception
        vulnerabilities = self.scanner.scan(test_file)
        # Syntax errors might be caught and return empty list or specific errors
        assert isinstance(vulnerabilities, list)

    def test_scanner_with_custom_config(self):
        """Test scanner initialization with custom configuration."""
        config = {
            'scan': {
                'exclude_dirs': ['.git', '__pycache__'],
                'max_file_size': 10485760,
            }
        }
        
        scanner = SecurityScanner(config=config)
        assert scanner.config == config

    def test_vulnerability_structure(self):
        """Test that vulnerabilities have expected structure."""
        test_code = '''
import pickle
data = pickle.loads(user_input)
'''
        test_file = os.path.join(self.test_dir, "test_deserialization.py")
        with open(test_file, 'w') as f:
            f.write(test_code)

        vulnerabilities = self.scanner.scan(test_file)
        
        if vulnerabilities:  # If any vulnerabilities found
            vuln = vulnerabilities[0]
            expected_keys = ['type', 'severity', 'file_path', 'line_number', 'description']
            
            for key in expected_keys:
                assert key in vuln
            assert isinstance(vuln['type'], str)
            assert isinstance(vuln['severity'], str)
            assert isinstance(vuln['file_path'], str)
            assert isinstance(vuln['line_number'], int)
            assert isinstance(vuln['description'], str)