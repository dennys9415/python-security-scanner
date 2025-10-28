import os
from typing import Optional, Any


def safe_open(file_path: str, mode: str = 'r', encoding: str = 'utf-8') -> Optional[Any]:
    """Safely open a file with error handling."""
    try:
        return open(file_path, mode, encoding=encoding)
    except (IOError, OSError, UnicodeDecodeError) as e:
        print(f"Warning: Could not open {file_path}: {e}")
        return None


def format_code_snippet(code: str, max_length: int = 100) -> str:
    """Format code snippet for display."""
    if len(code) > max_length:
        return code[:max_length] + "..."
    return code