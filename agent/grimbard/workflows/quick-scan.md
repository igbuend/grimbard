# Quick Security Scan Workflow

**Duration**: 15-30 minutes
**Purpose**: Fast automated security feedback for CI/CD pipelines and pre-commit checks
**Phases**: Discovery, Automated Analysis, Basic Triage (Phases 1-3 only)

---

## Overview

The Quick Scan workflow provides rapid security feedback by running automated static analysis tools and performing basic triage. It's designed for:

- **CI/CD Integration** - Fast feedback in build pipelines
- **Pre-commit Hooks** - Developer quick checks before commits
- **Initial Assessment** - First pass vulnerability identification
- **Incremental Scans** - Changed files only scanning

This workflow executes **Phases 1-3** of the complete security review, skipping deep manual review and variant analysis for speed.

---

## Prerequisites

### Required Tools

All tools must be installed and accessible in PATH:

- **Opengrep/Semgrep** - `opengrep --version` or `semgrep --version`
- **Gitleaks** - `gitleaks version`
- **KICS** - `kics version`
- **Noir** - `noir --version`
- **OSV-Scanner** - `osv-scanner --version`
- **Depscan** - `depscan --version`
- **Application Inspector** - `appinspector --version`

### Environment Setup

```bash
# Set output directory (optional)
export GRIMBARD_OUTPUT_DIR=./security-scan-output

# Set severity threshold (optional: error, warning, note, info)
export GRIMBARD_SEVERITY_THRESHOLD=warning
```

---

## Phase 1: Discovery & Reconnaissance (5 minutes)

### Objective

Quickly understand the codebase structure and identify high-value targets for security scanning.

### Steps

#### 1.1 Repository Structure Analysis

```bash
# Count lines of code by language
cloc /path/to/project --json > codebase-stats.json

# Identify technology stack
ls /path/to/project | grep -E "package.json|requirements.txt|go.mod|Gemfile|pom.xml|build.gradle"

# Find configuration files
find /path/to/project -type f -name "*.env*" -o -name "config.*" -o -name "*.yaml" -o -name "*.yml" | head -20
```

#### 1.2 Dependency Analysis

```bash
# Node.js
if [ -f package.json ]; then
  cat package.json | jq '.dependencies, .devDependencies'
fi

# Python
if [ -f requirements.txt ]; then
  cat requirements.txt
fi

# Go
if [ -f go.mod ]; then
  cat go.mod | grep require
fi

# Java
if [ -f pom.xml ]; then
  grep "<dependency>" pom.xml | head -10
fi
```

#### 1.3 Entry Point Discovery (with Noir)

```bash
# Discover API endpoints and attack surface
noir -b /path/to/project \
  --format sarif \
  -o ./security-scan-output/sarif/noir.sarif

# Generate summary
noir -b /path/to/project --format markdown-table
```

**Output**: Understanding of codebase size, tech stack, dependencies, and attack surface

---

## Phase 2: Automated Static Analysis (10-15 minutes)

### Objective

Run all security scanning tools in parallel for maximum speed.

### Parallel Execution Strategy

All tools run simultaneously. Create a script for parallel execution:

```bash
#!/bin/bash
# quick-scan-parallel.sh

OUTPUT_DIR="./security-scan-output/sarif"
PROJECT_PATH="/path/to/project"

mkdir -p "$OUTPUT_DIR"

# Function to run tool and log
run_tool() {
  local name=$1
  local cmd=$2
  echo "[$(date)] Starting $name..."
  eval "$cmd" > "$OUTPUT_DIR/$name.log" 2>&1
  echo "[$(date)] Completed $name"
}

# Run all tools in background
run_tool "opengrep" "opengrep scan --sarif --output $OUTPUT_DIR/opengrep.sarif $PROJECT_PATH" &
run_tool "gitleaks" "gitleaks detect --source=$PROJECT_PATH --report-format=sarif --report-path=$OUTPUT_DIR/gitleaks.sarif --no-banner --no-color" &
run_tool "kics" "kics scan -p $PROJECT_PATH --report-formats sarif --output-path $OUTPUT_DIR/kics.sarif" &
run_tool "osv-scanner" "osv-scanner scan --format sarif $PROJECT_PATH > $OUTPUT_DIR/osv-scanner.sarif" &
run_tool "depscan" "depscan --src $PROJECT_PATH --reports-dir $OUTPUT_DIR --report-template sarif" &
run_tool "app-inspector" "appinspector analyze -s $PROJECT_PATH --output-file-format sarif --output-file-path $OUTPUT_DIR/app-inspector.sarif" &

# Wait for all background jobs
wait

echo "[$(date)] All tools completed"
```

### Individual Tool Commands

If running sequentially or debugging individual tools:

#### 2.1 Opengrep (SAST)

```bash
opengrep scan \
  --sarif \
  --output ./security-scan-output/sarif/opengrep.sarif \
  --config auto \
  /path/to/project
```

**Expected Runtime**: 3-5 minutes
**What It Finds**: Injection flaws, XSS, insecure crypto, hardcoded secrets, auth issues

#### 2.2 Gitleaks (Secrets Detection)

```bash
gitleaks detect \
  --source=/path/to/project \
  --report-format=sarif \
  --report-path=./security-scan-output/sarif/gitleaks.sarif \
  --no-banner \
  --no-color \
  --redact
```

**Expected Runtime**: 1-2 minutes
**What It Finds**: API keys, passwords, tokens, private keys, credentials

#### 2.3 KICS (IaC Security)

```bash
kics scan \
  -p /path/to/project \
  --report-formats sarif \
  --output-path ./security-scan-output/sarif/kics.sarif \
  --exclude-paths node_modules,vendor,.git
```

**Expected Runtime**: 2-4 minutes
**What It Finds**: Terraform misconfigurations, K8s security issues, Dockerfile vulnerabilities

#### 2.4 OSV-Scanner (Dependency Vulnerabilities)

```bash
osv-scanner scan \
  --format sarif \
  /path/to/project > ./security-scan-output/sarif/osv-scanner.sarif
```

**Expected Runtime**: 1-3 minutes (network dependent)
**What It Finds**: Known CVEs in dependencies, outdated packages

#### 2.5 Depscan (Advanced SCA)

```bash
depscan \
  --src /path/to/project \
  --reports-dir ./security-scan-output \
  --report-template sarif
```

**Expected Runtime**: 2-4 minutes
**What It Finds**: Dependency vulnerabilities, license issues, SBOM generation

#### 2.6 Application Inspector (Technology Profiling)

```bash
appinspector analyze \
  -s /path/to/project \
  --output-file-format sarif \
  --output-file-path ./security-scan-output/sarif/app-inspector.sarif
```

**Expected Runtime**: 1-2 minutes
**What It Finds**: Crypto usage, authentication frameworks, data handling patterns

**Output**: 6-7 SARIF files with automated findings

---

## Phase 3: Basic Triage & Prioritization (5-10 minutes)

### Objective

Consolidate findings and apply severity-based prioritization for actionable output.

### Steps

#### 3.1 SARIF Consolidation

Use the `sarif-issue-reporter` skill to aggregate all SARIF files:

```bash
# Consolidate all SARIF files
python -m sarif_tools summary \
  ./security-scan-output/sarif/*.sarif \
  --output ./security-scan-output/sarif/consolidated.sarif
```

#### 3.2 Severity-Based Ranking

```bash
# Generate findings by severity
python -m sarif_tools diff \
  --output-format markdown \
  ./security-scan-output/sarif/consolidated.sarif \
  > ./security-scan-output/findings-summary.md
```

#### 3.3 Priority Assignment

Apply this priority matrix:

| SARIF Level | Exploitability | Priority | Action Required |
|-------------|----------------|----------|-----------------|
| error | High | **P0 - Critical** | Fix immediately, block deployment |
| error | Medium | **P1 - High** | Fix before release |
| warning | High | **P1 - High** | Fix before release |
| warning | Medium | **P2 - Medium** | Fix in current sprint |
| note | Any | **P3 - Low** | Backlog item |
| info | Any | **P3 - Low** | Document or suppress |

#### 3.4 False Positive Filtering

Quick false positive checks:

```bash
# Check for common false positives
grep -E "test/|spec/|mock/|fixture/" ./security-scan-output/sarif/consolidated.sarif

# Review findings in test code (usually lower priority)
# Review findings in generated code (often suppressible)
```

#### 3.5 Generate Quick Report

```bash
# Create markdown summary
cat > ./security-scan-output/quick-scan-report.md << 'EOF'
# Quick Security Scan Report

**Scan Date**: $(date)
**Project**: /path/to/project

## Summary

- **Total Findings**: [Count from SARIF]
- **Critical (P0)**: [Count]
- **High (P1)**: [Count]
- **Medium (P2)**: [Count]
- **Low (P3)**: [Count]

## Top 10 Priority Findings

[List top 10 by severity and exploitability]

## Tool Coverage

- ✓ Opengrep - Code patterns and vulnerabilities
- ✓ Gitleaks - Secrets detection
- ✓ KICS - Infrastructure as Code
- ✓ OSV-Scanner - Dependency vulnerabilities
- ✓ Depscan - Advanced SCA
- ✓ Application Inspector - Technology profiling

## Next Steps

1. Review P0/P1 findings immediately
2. Create tickets for P2 findings
3. Run complete security review (`/grimbard-review`) for deep analysis
EOF
```

**Output**: Prioritized findings list, quick report, consolidated SARIF

---

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Quick Security Scan

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Install security tools
        run: |
          pip install semgrep gitleaks kics osv-scanner depscan

      - name: Run Grimbard Quick Scan
        run: |
          # Run quick scan workflow
          /grimbard-quick .

      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: security-scan-output/sarif/

      - name: Check for critical findings
        run: |
          # Fail build if P0 findings exist
          if grep -q '"level": "error"' security-scan-output/sarif/consolidated.sarif; then
            echo "Critical security findings detected"
            exit 1
          fi
```

### GitLab CI Example

```yaml
security-scan:
  stage: test
  image: python:3.11

  before_script:
    - pip install semgrep gitleaks kics osv-scanner depscan

  script:
    - /grimbard-quick .

  artifacts:
    reports:
      sast: security-scan-output/sarif/*.sarif
    paths:
      - security-scan-output/

  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

---

## Output Structure

```
security-scan-output/
├── sarif/
│   ├── opengrep.sarif
│   ├── gitleaks.sarif
│   ├── kics.sarif
│   ├── noir.sarif
│   ├── osv-scanner.sarif
│   ├── depscan.sarif
│   ├── app-inspector.sarif
│   └── consolidated.sarif
├── quick-scan-report.md
├── findings-summary.md
└── logs/
    ├── opengrep.log
    ├── gitleaks.log
    └── [other tool logs]
```

---

## Performance Optimization

### Incremental Scanning (Changed Files Only)

For faster scans on large repositories:

```bash
# Get changed files in current branch
CHANGED_FILES=$(git diff --name-only origin/main...HEAD)

# Run opengrep on changed files only
echo "$CHANGED_FILES" | xargs opengrep scan --sarif --output results.sarif

# Note: Some tools (OSV-Scanner, Depscan) need full repo context
```

### Caching Strategies

```bash
# Cache dependency scan results (reuse if lock files unchanged)
LOCK_FILE_HASH=$(md5sum package-lock.json requirements.txt go.sum 2>/dev/null | md5sum)

if [ -f "cache/osv-scanner-$LOCK_FILE_HASH.sarif" ]; then
  echo "Using cached dependency scan"
  cp "cache/osv-scanner-$LOCK_FILE_HASH.sarif" ./security-scan-output/sarif/osv-scanner.sarif
else
  osv-scanner scan --format sarif . > ./security-scan-output/sarif/osv-scanner.sarif
  cp ./security-scan-output/sarif/osv-scanner.sarif "cache/osv-scanner-$LOCK_FILE_HASH.sarif"
fi
```

---

## Limitations

### What Quick Scan Does NOT Include

- **No deep manual review** - Authentication, authorization, crypto review skipped
- **No variant analysis** - Similar pattern exploration not performed
- **No threat modeling** - Attack scenario analysis not included
- **No code flow analysis** - Cross-file data flow not traced
- **Limited false positive filtering** - Basic checks only

### When to Use Complete Review Instead

Use `/grimbard-review` (complete security review) when:

- Pre-release security audit required
- Compliance certification needed
- Critical application or sensitive data
- Complex authentication/authorization logic
- Cryptographic operations present
- Previous security incidents occurred

---

## Troubleshooting

### Tool Not Found

```bash
# Verify tool installation
which opengrep semgrep gitleaks kics noir osv-scanner depscan appinspector

# Install missing tools
pip install semgrep gitleaks
brew install kics noir
go install github.com/google/osv-scanner/cmd/osv-scanner@latest
```

### Scan Timeout

```bash
# Increase timeout for large repositories
export GRIMBARD_TOOL_TIMEOUT=1800  # 30 minutes per tool

# Or run tools individually
/grimbard-quick --tool=opengrep
/grimbard-quick --tool=gitleaks
```

### High False Positive Rate

```bash
# Configure tool exclusions
# Create config/tools.yml with exclusions:

opengrep:
  exclude:
    - "test/**"
    - "tests/**"
    - "**/*_test.go"
    - "**/*_spec.rb"
```

---

## Success Criteria

Quick scan is successful when:

- ✓ All 6-7 tools complete execution
- ✓ SARIF files generated for each tool
- ✓ Consolidated SARIF created
- ✓ Quick report generated
- ✓ Total runtime under 30 minutes
- ✓ P0/P1 findings identified and reported

---

## Next Steps After Quick Scan

### If P0/P1 Findings Exist

1. Review findings immediately
2. Create tickets for remediation
3. Fix critical issues
4. Re-run quick scan to verify fixes

### If Only P2/P3 Findings

1. Add to backlog
2. Schedule for upcoming sprint
3. Run complete review (`/grimbard-review`) for deeper analysis

### For Ongoing Security

1. Integrate quick scan into CI/CD
2. Run weekly triage (`/grimbard-triage`)
3. Run quarterly complete reviews
4. Track security metrics over time

---

## References

- [Complete Security Review Workflow](secure-code-review.md)
- [Vulnerability Triage Workflow](vulnerability-triage.md)
- [SARIF Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/)
- [CI/CD Security Best Practices](https://owasp.org/www-project-devsecops-guideline/)
