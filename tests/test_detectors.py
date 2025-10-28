import pytest
import ast
from src.security_scanner.detectors import (
    SQLInjectionDetector,
    XSSDetector,
    CommandInjectionDetector,
    HardcodedSecretsDetector
)


class TestDetectors:
    def test_sql_injection_detector(self):
        detector = SQLInjectionDetector()
        code = "cursor.execute('SELECT * FROM users WHERE name = %s' % user_input)"
        tree = ast.parse(code)
        
        vulnerabilities = []
        for node in ast.walk(tree):
            vulnerabilities.extend(detector.analyze(node, "test.py"))
        
        assert len(vulnerabilities) > 0
        assert vulnerabilities[0]['type'] == 'SQL Injection'
    
    def test_command_injection_detector(self):
        detector = CommandInjectionDetector()
        code = "os.system(user_input)"
        tree = ast.parse(code)
        
        vulnerabilities = []
        for node in ast.walk(tree):
            vulnerabilities.extend(detector.analyze(node, "test.py"))
        
        assert len(vulnerabilities) > 0
        assert vulnerabilities[0]['type'] == 'Command Injection'
    
    def test_hardcoded_secrets_detector(self):
        detector = HardcodedSecretsDetector()
        code = "password = 'my_secret_password123'"
        tree = ast.parse(code)
        
        vulnerabilities = []
        for node in ast.walk(tree):
            vulnerabilities.extend(detector.analyze(node, "test.py"))
        
        assert len(vulnerabilities) > 0
        assert vulnerabilities[0]['type'] == 'Hardcoded Secret'