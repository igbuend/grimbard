# SARIF Issue Reporter

Analyze SARIF security scan results and generate detailed vulnerability reports with CVSS scoring, exploitation scenarios, and remediation guidance.

## Quick Start

### 1. With Claude

Upload your SARIF file and use the skill:

```
Analyze results.sarif and generate a security report for critical issues
```

Or invoke directly:

```
/sarif-issue-reporter results.sarif
```

### 2. With Helper Script

```bash
# View statistics
python scripts/sarif_helper.py results.sarif --stats-only

# Filter by severity and generate report template
python scripts/sarif_helper.py results.sarif --severity error --output report.md
```

## Package Contents

```
sarif-issue-reporter/
├── SKILL.md              # Main skill documentation
├── README.md             # This file
└── scripts/
    └── sarif_helper.py   # Python utility for SARIF parsing
```

## Helper Script Usage

```bash
# Basic usage
python scripts/sarif_helper.py <sarif_file> [options]

# Options
--severity error,warning    # Filter by severity levels
--output report.md          # Output file for report template
--run 0                     # Run index to analyze (default: 0)
--stats-only                # Only show statistics
```

### Example Output

```
SARIF Version: 2.1.0
Number of runs: 1
Tool: SecurityScanner v2.5.0

Severity Distribution:
  Critical/Error: 3
  Warning: 1
  Note/Info: 0

Files with issues: 4
```

## Supported SARIF Sources

Works with SARIF 2.1.0 output from:
- Semgrep, CodeQL, SonarQube, Snyk
- Checkmarx, Fortify, ESLint, Bandit, SpotBugs
- Any SARIF 2.1.0 compliant tool

## CI/CD Integration

```yaml
# GitHub Actions example
- name: Run Security Scan
  run: semgrep --config=auto --sarif > results.sarif

- name: Generate Report Template
  run: python scripts/sarif_helper.py results.sarif --output report.md
```

## Resources

- [SARIF 2.1.0 Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [CVSS 3.1 Calculator](https://www.first.org/cvss/calculator/3.1)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Database](https://cwe.mitre.org/)

## Version

- **0.0.1** (2025-01-18): Initial release
- **Author**: Herman Stevens
