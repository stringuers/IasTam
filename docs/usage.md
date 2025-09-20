# DefenSys Usage Guide

Learn how to use DefenSys to scan your applications for security vulnerabilities.

## 🚀 Quick Start

### Basic Scan

```bash
# Scan a directory
defensys ./my-project

# Scan with recursive search
defensys ./my-project -r

# Scan specific file types
defensys ./my-project --extensions js,ts,py
```

### Output Formats

```bash
# Console output (default)
defensys ./my-project -f console

# HTML report
defensys ./my-project -f html -o report.html

# JSON output
defensys ./my-project -f json -o results.json
```

## 🔧 Command Line Options

### Basic Options

| Option | Description | Example |
|--------|-------------|---------|
| `-r, --recursive` | Scan recursively | `defensys ./project -r` |
| `-f, --format` | Output format | `defensys ./project -f html` |
| `-o, --output` | Output file | `defensys ./project -o report.html` |
| `--extensions` | File extensions | `defensys ./project --extensions js,py` |
| `--deep` | Deep analysis | `defensys ./project --deep` |

### Advanced Options

| Option | Description | Example |
|--------|-------------|---------|
| `--config` | Config file | `defensys ./project --config config.json` |
| `--exclude` | Exclude patterns | `defensys ./project --exclude node_modules` |
| `--timeout` | Scan timeout | `defensys ./project --timeout 600` |
| `--parallel` | Parallel scans | `defensys ./project --parallel 8` |

### API Server

```bash
# Start API server
defensys --api

# Custom host and port
defensys --api --host 0.0.0.0 --port 9000

# With workers
defensys --api --workers 4
```

## 📊 Understanding Results

### Vulnerability Severity Levels

- **🔴 Critical**: Immediate action required
- **🟠 High**: Should be fixed soon
- **🟡 Medium**: Fix when possible
- **🟢 Low**: Consider fixing
- **ℹ️ Info**: Informational only

### Report Sections

1. **Summary**: Overview of findings
2. **Vulnerabilities**: Detailed vulnerability list
3. **Attack Chains**: Potential exploit paths
4. **Recommendations**: Security suggestions

## 🎯 Scanning Strategies

### Development Scanning

```bash
# Quick scan during development
defensys ./src --extensions js,ts --format console

# Deep scan before commit
defensys ./src --deep --format html -o pre-commit-report.html
```

### Production Scanning

```bash
# Comprehensive production scan
defensys ./app --recursive --deep --format html -o production-scan.html

# CI/CD integration
defensys ./app --format json -o ci-results.json
```

### Custom Configuration

Create a `defensys.json` file:

```json
{
  "scan": {
    "recursive": true,
    "file_extensions": [".js", ".ts", ".py", ".java"],
    "exclude_patterns": ["node_modules", ".git", "dist"],
    "deep_analysis": true,
    "parallel_scans": 8
  },
  "detection": {
    "sql_injection": {
      "enabled": true,
      "severity_threshold": "medium"
    },
    "xss": {
      "enabled": true,
      "severity_threshold": "high"
    }
  },
  "report": {
    "include_poc": true,
    "generate_attack_chains": true,
    "export_formats": ["html", "json"]
  }
}
```

## 🔌 API Usage

### REST API Endpoints

#### Health Check
```bash
curl http://localhost:8000/health
```

#### Start Scan
```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target_path": "/path/to/project",
    "recursive": true,
    "deep_analysis": false
  }'
```

#### Get Scan Results
```bash
curl http://localhost:8000/scan/scan-id
```

### Python API

```python
from defensys import DefenSysAnalyzer, ScanConfig

# Initialize analyzer
analyzer = DefenSysAnalyzer()

# Configure scan
scan_config = ScanConfig(
    target_path="./my-project",
    recursive=True,
    deep_analysis=True
)

# Run scan
results = await analyzer.scan(scan_config)

# Process results
for vulnerability in results['vulnerabilities']:
    print(f"Found {vulnerability['title']} in {vulnerability['location']['file_path']}")
```

## 🔄 CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'
      - name: Install DefenSys
        run: pip install defensys-scanner
      - name: Run Security Scan
        run: defensys ./src --format json -o security-results.json
      - name: Upload Results
        uses: actions/upload-artifact@v2
        with:
          name: security-results
          path: security-results.json
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'defensys ./src --format html -o security-report.html'
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: '.',
                    reportFiles: 'security-report.html',
                    reportName: 'Security Report'
                ])
            }
        }
    }
}
```

## 🛠️ Custom Rules

### Creating Custom Patterns

```python
from defensys.analyzers.pattern_matcher import DetectionPattern, PatternMatcher
from defensys.models.vulnerability import VulnerabilityType, Severity

# Create custom pattern
custom_pattern = DetectionPattern(
    name="Custom SQL Injection",
    pattern=r"db\.query\s*\(\s*[\"'].*?\+.*?[\"']",
    vulnerability_type=VulnerabilityType.SQL_INJECTION,
    severity=Severity.HIGH,
    description="Custom SQL injection pattern",
    cwe_id="CWE-89",
    fix_suggestion="Use parameterized queries"
)

# Add to pattern matcher
matcher = PatternMatcher()
matcher.add_custom_pattern(custom_pattern)
```

### Custom Analyzers

```python
from defensys.analyzers import BaseAnalyzer

class CustomAnalyzer(BaseAnalyzer):
    async def analyze(self, context):
        vulnerabilities = []
        # Your custom analysis logic
        return vulnerabilities
```

## 📈 Performance Optimization

### Large Codebases

```bash
# Use parallel scanning
defensys ./large-project --parallel 16

# Exclude unnecessary directories
defensys ./large-project --exclude node_modules,dist,build

# Limit file size
defensys ./large-project --max-file-size 10
```

### Memory Optimization

```bash
# Process files in batches
defensys ./project --batch-size 100

# Disable deep analysis for large scans
defensys ./project --no-deep
```

## 🔍 Troubleshooting

### Common Issues

#### Scan Hangs
```bash
# Increase timeout
defensys ./project --timeout 1800

# Check for large files
defensys ./project --max-file-size 50
```

#### Memory Issues
```bash
# Reduce parallel scans
defensys ./project --parallel 2

# Exclude large directories
defensys ./project --exclude node_modules,dist
```

#### False Positives
```bash
# Adjust confidence threshold
defensys ./project --confidence 0.8

# Use custom rules
defensys ./project --rules custom-rules.json
```

## 📚 Examples

Check out the [examples directory](../examples/) for more usage examples:

- [Basic Scan](../examples/basic_scan.py)
- [Advanced Configuration](../examples/advanced_configuration.py)
- [Custom Rules](../examples/custom_rules.py)
- [API Integration](../examples/api_integration.py)

## 🤝 Getting Help

- **Documentation**: [docs.defensys.ai](https://docs.defensys.ai)
- **GitHub Issues**: [github.com/defensys/scanner/issues](https://github.com/defensys/scanner/issues)
- **Discord**: [discord.gg/defensys](https://discord.gg/defensys)
- **Email**: support@defensys.ai

---

*Usage guide last updated: 2024-01-01*
