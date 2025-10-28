import pytest
from src.security_scanner.utils.helpers import safe_open, format_code_snippet


class TestUtils:
    def test_safe_open_nonexistent(self):
        result = safe_open('/nonexistent/file/path.txt')
        assert result is None
    
    def test_format_code_snippet(self):
        long_code = "x" * 150
        result = format_code_snippet(long_code, max_length=100)
        assert len(result) == 103  # 100 chars + "..."
        assert result.endswith("...")
    
    def test_format_code_snippet_short(self):
        short_code = "x" * 50
        result = format_code_snippet(short_code, max_length=100)
        assert result == short_code