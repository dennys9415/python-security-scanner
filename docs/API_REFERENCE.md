# API Reference

## SecurityScanner

Main scanner class.

### Methods

#### `scan(target: str) -> List[Dict]`
Scan a file or directory for vulnerabilities.

**Parameters:**
- `target`: Path to file or directory

**Returns:** List of vulnerability dictionaries

#### `generate_report(vulnerabilities, output_path, format)`
Generate a vulnerability report.

**Parameters:**
- `vulnerabilities`: List of vulnerabilities from scan()
- `output_path`: Output file path
- `format`: Report format ('html', 'json', 'console')

## VulnerabilityDetector

Orchestrates vulnerability detection.

### Methods

#### `analyze_ast(tree, file_path)`
Analyze AST tree for vulnerabilities.

#### `get_available_detectors()`
Get list of available detector names.

## Custom Detectors

Create custom detectors by implementing:

```python
class CustomDetector:
    def analyze(self, node: ast.AST, file_path: str) -> List[Dict]:
        # Your detection logic
        return vulnerabilities
```

