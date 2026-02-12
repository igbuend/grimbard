---
name: sarif-tools
description: "Process, analyze, and transform SARIF files using Microsoft's sarif-tools CLI. Use when consolidating SARIF outputs from multiple scanners, generating CSV/HTML/Word reports, diffing scan results between builds, filtering findings, adding git blame information, or producing Code Climate reports for GitLab."
---

# SARIF Tools

Microsoft's [sarif-tools](https://github.com/microsoft/sarif-tools) — a Python CLI and library for working with SARIF (Static Analysis Results Interchange Format) files.

## Installation

```bash
# pip
pip install sarif-tools

# pipx (recommended — isolated environment)
pipx install sarif-tools

# Verify
sarif --version
```

If `sarif` is not on PATH after install, use `python -m sarif` instead.

## Commands

| Command | Purpose |
|---------|---------|
| `summary` | Text summary with issue counts by severity and tool |
| `csv` | Export issues to CSV for spreadsheet analysis |
| `html` | Generate HTML report for browser viewing |
| `word` | Generate MS Word (.docx) summary report |
| `diff` | Compare two sets of SARIF files (new vs old findings) |
| `copy` | Merge/filter SARIF files into a single consolidated file |
| `blame` | Augment SARIF with git blame info (who last modified each line) |
| `codeclimate` | Convert to Code Climate JSON for GitLab Code Quality reports |
| `info` | Print structural information about SARIF files |
| `ls` | List all SARIF files in a directory |
| `trend` | Generate CSV time series from timestamped SARIF files |
| `emacs` | Output in emacs-compatible format |

## Usage Examples

### Summarize Findings

```bash
# Summary of a single file
sarif summary scan-results.sarif

# Summary of all SARIF files in a directory
sarif summary ./sarif-output/
```

Output shows counts by severity (error, warning, note) grouped by tool and rule.

### Consolidate Multiple SARIF Files

```bash
# Merge all SARIF files into one
sarif copy -o consolidated.sarif ./sarif-output/

# Merge with timestamp in filename (for trend tracking)
sarif copy -o consolidated.sarif --timestamp ./sarif-output/
```

### Export to CSV

```bash
# Basic CSV export
sarif csv -o findings.csv ./sarif-output/

# Strip common path prefix for cleaner output
sarif csv --autotrim -o findings.csv ./sarif-output/

# Strip specific prefix
sarif csv --trim /home/user/project -o findings.csv ./sarif-output/
```

CSV includes columns: severity, rule ID, message, file, line. If blame info is present, includes author.

### Generate HTML Report

```bash
sarif html -o report.html ./sarif-output/
```

### Generate Word Report

```bash
sarif word -o report.docx ./sarif-output/
```

### Diff Between Builds

```bash
# Compare old vs new scan results
sarif diff ./old-sarif/ ./new-sarif/

# Output diff to JSON file
sarif diff -o diff-report.json ./old-sarif/ ./new-sarif/

# Exit with error if new issues at warning level or above
sarif diff --check warning ./old-sarif/ ./new-sarif/
```

### Add Git Blame Information

```bash
# Augment SARIF with blame info (run from git repo root)
sarif blame -o ./blamed-sarif/ ./sarif-output/

# Specify git repo path explicitly
sarif blame -o ./blamed-sarif/ -c /path/to/repo ./sarif-output/
```

Adds author, commit, timestamp to each finding's property bag. Enables author-based filtering and CSV author column.

### Code Climate for GitLab

```bash
# Generate Code Climate JSON for GitLab merge request UI
sarif codeclimate -o codeclimate.json ./sarif-output/
```

Publish as a Code Quality artifact in GitLab CI pipeline.

### Filtering

After running `sarif blame`, use filter files to include/exclude findings by author, date, or other blame properties:

```bash
# Apply filter to CSV export
sarif csv --filter my-filter.yaml -o filtered.csv ./blamed-sarif/

# Apply filter to copy (consolidated output)
sarif copy --filter my-filter.yaml -o filtered.sarif ./blamed-sarif/
```

Filter file format (YAML):
```yaml
# Include only findings from specific authors
include:
  author:
    - "developer@company.com"

# Exclude findings from specific authors
exclude:
  author:
    - "bot@company.com"
```

### CI/CD Integration

```bash
# Exit with error code if any error-level findings exist
sarif --check error summary ./sarif-output/

# Exit with error code if any warning-or-above findings exist
sarif --check warning summary ./sarif-output/

# Check for regressions between builds
sarif diff --check warning ./baseline-sarif/ ./current-sarif/
```

### File Discovery

```bash
# List all SARIF files in a directory tree
sarif ls ./project-output/

# Get structural info about SARIF files
sarif info ./sarif-output/
```

### Trend Analysis

```bash
# Generate CSV time series from timestamped SARIF files
# Files must have timestamps in filenames: myapp_tool_20260212T120000Z.sarif
sarif trend -o trend.csv ./sarif-history/
```

## SARIF Format Notes

SARIF v2.1.0 is the standard format. Key fields used by sarif-tools:

- **Severity levels**: `error`, `warning`, `note`, `none`
- **Result fields**: `ruleId`, `message`, `level`, `locations`, `codeFlows`
- **Location**: `physicalLocation.artifactLocation.uri` + `region.startLine`

Different tools map their severity levels differently. sarif-tools handles common variations, but some tools may need preprocessing for best results.

## Glob Patterns

All commands accept glob patterns for input:

```bash
# Process all devskim SARIF files recursively
sarif summary "./output/**/devskim*.sarif"
```

## Python Library Usage

```python
from sarif import loader

# Load SARIF files
sarif_files = loader.loader("./sarif-output/")

# Access results programmatically
for run in sarif_files:
    for result in run.get_results():
        print(result.get("ruleId"), result.get("level"))
```

## References

- **Repository**: https://github.com/microsoft/sarif-tools
- **PyPI**: https://pypi.org/project/sarif-tools/
- **SARIF Standard**: https://sarifweb.azurewebsites.net/
- **SARIF Spec (OASIS)**: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
