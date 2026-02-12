---
name: codeql
description: Run CodeQL static analysis for security vulnerability detection, taint tracking, and data flow analysis. Use when asked to scan code with CodeQL, write QL queries, perform deep interprocedural analysis, or integrate with GitHub Advanced Security.
aliases:
  - code-ql
  - github-codeql
allowed-tools:
  - Bash
  - Read
  - Glob
  - Grep
---

# CodeQL Static Analysis

## When to Use CodeQL

**Ideal scenarios:**

- Deep interprocedural taint tracking across files and modules
- Complex data flow analysis requiring semantic understanding
- Security vulnerability detection in large codebases
- Finding vulnerabilities that span multiple function calls
- Variant analysis (finding similar bugs across codebase)
- GitHub Advanced Security integration
- Compliance-driven security scanning
- Custom query development for organization-specific patterns

**Complements other tools:**

- Use after Semgrep for deeper analysis of flagged areas
- Combine with SARIF Issue Reporter for detailed findings
- Pair with dependency scanners (OSV-Scanner) for supply chain
- Use alongside Gitleaks for secrets detection

**Consider Semgrep instead when:**

- Need quick pattern-based scans (minutes vs hours)
- Simple intra-file pattern matching sufficient
- Writing rules without learning QL language
- CI/CD needs fast feedback loops

## When NOT to Use

Do NOT use this skill for:

- Quick pattern-based scans (use Semgrep)
- Secrets detection (use Gitleaks)
- Dependency vulnerability scanning (use OSV-Scanner, Depscan)
- IaC security analysis (use KICS)
- API endpoint discovery (use Noir)
- Binary analysis without source code
- Languages not supported by CodeQL

## Supported Languages

| Language | Database | Maturity |
|----------|----------|----------|
| C/C++ | `cpp` | Stable |
| C# | `csharp` | Stable |
| Go | `go` | Stable |
| Java/Kotlin | `java` | Stable |
| JavaScript/TypeScript | `javascript` | Stable |
| Python | `python` | Stable |
| Ruby | `ruby` | Stable |
| Swift | `swift` | Beta |

## Installation

### GitHub CLI (Recommended)

```bash
# Install CodeQL CLI via GitHub CLI
gh extension install github/gh-codeql

# Verify installation
gh codeql version
```

### Direct Download

```bash
# Download latest release (Linux/macOS)
wget https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip
unzip codeql-linux64.zip
export PATH="$PWD/codeql:$PATH"

# Windows
# Download from: https://github.com/github/codeql-cli-binaries/releases

# Verify
codeql version
```

### Clone Standard Queries

```bash
# Clone CodeQL queries repository
git clone --depth 1 https://github.com/github/codeql.git codeql-repo

# Set CODEQL_HOME
export CODEQL_HOME="$PWD/codeql-repo"
```

### VS Code Extension

Install "CodeQL" extension from marketplace for query development and debugging.

## Core Workflow

### 1. Create Database

```bash
# Auto-detect language
codeql database create <db-name> --source-root=<source-path>

# Specify language explicitly
codeql database create my-db --language=python --source-root=./src

# Multiple languages
codeql database create my-db --language=javascript,python --source-root=.

# With build command (compiled languages)
codeql database create my-db --language=java --command="mvn clean compile" --source-root=.
codeql database create my-db --language=cpp --command="make" --source-root=.

# Overwrite existing database
codeql database create my-db --language=python --overwrite --source-root=.
```

### 2. Run Analysis

```bash
# Run default security queries
codeql database analyze <db-name> --format=sarif-latest --output=results.sarif

# Use specific query suite
codeql database analyze my-db codeql/python-queries:codeql-suites/python-security-extended.qls \
  --format=sarif-latest --output=results.sarif

# Run single query
codeql database analyze my-db path/to/query.ql --format=sarif-latest --output=results.sarif

# Multiple query packs
codeql database analyze my-db \
  codeql/javascript-queries \
  codeql/python-queries \
  --format=sarif-latest --output=results.sarif
```

### 3. Query Suites

| Suite | Description |
|-------|-------------|
| `<lang>-security-extended.qls` | Comprehensive security queries |
| `<lang>-security-and-quality.qls` | Security + code quality |
| `<lang>-code-scanning.qls` | GitHub code scanning default |
| `<lang>-lgtm-full.qls` | All available queries |

```bash
# Python security extended
codeql database analyze my-db \
  codeql/python-queries:codeql-suites/python-security-extended.qls \
  --format=sarif-latest --output=python-results.sarif

# JavaScript security
codeql database analyze my-db \
  codeql/javascript-queries:codeql-suites/javascript-security-extended.qls \
  --format=sarif-latest --output=js-results.sarif
```

## Output Formats

```bash
# SARIF (recommended for CI/CD)
codeql database analyze my-db --format=sarif-latest --output=results.sarif

# CSV
codeql database analyze my-db --format=csv --output=results.csv

# JSON
codeql database analyze my-db --format=json --output=results.json

# Text (human readable)
codeql database analyze my-db --format=text --output=results.txt

# SARIF with source snippets
codeql database analyze my-db --format=sarif-latest \
  --sarif-add-snippets --output=results.sarif
```

## Writing Custom Queries

### Basic Query Structure

```ql
/**
 * @name SQL injection vulnerability
 * @description User input flows to SQL query without sanitization
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id py/sql-injection
 * @tags security
 *       external/cwe/cwe-089
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import DataFlow::PathGraph

class SqlInjectionConfig extends TaintTracking::Configuration {
  SqlInjectionConfig() { this = "SqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(RemoteFlowSource remote | source = remote)
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(SqlExecution sql | sink = sql.getSql())
  }
}

from SqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "SQL injection from $@ to $@.", source.getNode(), "user input", sink.getNode(), "SQL query"
```

### Query Metadata

| Metadata | Description |
|----------|-------------|
| `@name` | Human-readable query name |
| `@description` | Detailed description |
| `@kind` | Query type: `problem`, `path-problem`, `metric` |
| `@problem.severity` | `error`, `warning`, `recommendation` |
| `@security-severity` | CVSS score (0.0-10.0) |
| `@precision` | `very-high`, `high`, `medium`, `low` |
| `@id` | Unique identifier (e.g., `py/sql-injection`) |
| `@tags` | Categories: `security`, `correctness`, `maintainability` |

### Data Flow vs Taint Tracking

| Feature | DataFlow | TaintTracking |
|---------|----------|---------------|
| **Tracks** | Exact values | Derived values |
| **Use case** | Value equality | Security flows |
| **Example** | "Is this exact password used?" | "Does user input reach SQL?" |
| **Sanitizers** | Not applicable | Supported |

## GitHub Actions Integration

### Basic Workflow

```yaml
name: CodeQL

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 0 * * 0'  # Weekly

jobs:
  analyze:
    name: Analyze
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write

    strategy:
      fail-fast: false
      matrix:
        language: ['javascript', 'python']

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: ${{ matrix.language }}
          queries: security-extended

      - name: Autobuild
        uses: github/codeql-action/autobuild@v3

      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v3
        with:
          category: "/language:${{ matrix.language }}"
```

### Custom Queries in CI

```yaml
- name: Initialize CodeQL
  uses: github/codeql-action/init@v3
  with:
    languages: python
    queries: security-extended,./custom-queries
    config-file: ./.github/codeql/codeql-config.yml
```

### CodeQL Config File

```yaml
# .github/codeql/codeql-config.yml
name: "Custom CodeQL Config"

queries:
  - uses: security-extended
  - uses: security-and-quality
  - uses: ./custom-queries

paths-ignore:
  - '**/test/**'
  - '**/tests/**'
  - '**/vendor/**'
  - '**/node_modules/**'

query-filters:
  - exclude:
      id: py/redundant-comparison
```

## CLI Quick Reference

| Command | Purpose |
|---------|---------|
| `codeql database create` | Create analysis database |
| `codeql database analyze` | Run queries against database |
| `codeql database upgrade` | Upgrade database schema |
| `codeql database bundle` | Package database for sharing |
| `codeql query compile` | Compile QL query |
| `codeql query run` | Run query directly |
| `codeql pack download` | Install query packs |
| `codeql pack ls` | List installed packs |
| `codeql pack init` | Create custom pack |

## Common Use Cases

### 1. Full Security Audit

```bash
# Create database
codeql database create audit-db --language=python --source-root=./app

# Run comprehensive security analysis
codeql database analyze audit-db \
  codeql/python-queries:codeql-suites/python-security-extended.qls \
  --format=sarif-latest \
  --sarif-add-snippets \
  --output=security-audit.sarif

# View results
cat security-audit.sarif | jq '.runs[].results[] | {rule: .ruleId, message: .message.text, location: .locations[0].physicalLocation.artifactLocation.uri}'
```

### 2. Variant Analysis

```bash
# Run custom query to find similar patterns
codeql query run variant.ql --database=my-db --output=variants.bqrs
codeql bqrs decode variants.bqrs --format=csv --output=variants.csv
```

### 3. Multi-Language Analysis

```bash
# Create databases for each language
codeql database create js-db --language=javascript --source-root=./frontend
codeql database create py-db --language=python --source-root=./backend

# Analyze separately
codeql database analyze js-db codeql/javascript-queries \
  --format=sarif-latest --output=frontend.sarif

codeql database analyze py-db codeql/python-queries \
  --format=sarif-latest --output=backend.sarif

# Merge SARIF results
jq -s '.[0].runs += .[1].runs | .[0]' frontend.sarif backend.sarif > combined.sarif
```

## Performance Optimization

```bash
# Increase memory for large codebases
codeql database analyze my-db --ram=8192 --threads=4 ...

# Use compilation cache
export CODEQL_COMPILATION_CACHE="$HOME/.codeql/cache"

# Incremental analysis (reuse database)
codeql database create my-db --overwrite=false ...

# Limit query timeout
codeql database analyze my-db --timeout=600 ...
```

## Troubleshooting

### Common Issues

```bash
# Database creation fails - check build command
codeql database create my-db --language=java --command="mvn -X compile" ...

# Query compilation errors
codeql query compile --warnings=show query.ql

# Missing dependencies
codeql pack download codeql/python-all

# Database version mismatch
codeql database upgrade my-db

# Debug query execution
codeql query run query.ql --database=my-db --output=debug.bqrs -- --dump-ra
```

### Validation

```bash
# Validate SARIF output
codeql database analyze my-db --format=sarif-latest --output=results.sarif
jq '.runs[0].results | length' results.sarif

# Check query metadata
codeql query metadata query.ql

# Test query against expected results
codeql test run tests/
```

## Limitations

- **Build required**: Compiled languages need successful build
- **Analysis time**: Deep analysis can take hours on large codebases
- **Memory usage**: Large databases require significant RAM (8GB+)
- **Learning curve**: QL language requires dedicated learning
- **Language coverage**: Not all languages equally supported
- **False positives**: Complex flows may produce FPs requiring tuning

## Rationalizations to Reject

| Shortcut | Why It's Wrong |
|----------|----------------|
| "CodeQL found nothing, code is secure" | CodeQL queries cover known patterns; novel vulnerabilities need custom queries |
| "Too slow for CI" | Use caching, incremental analysis, or run on schedule instead of every PR |
| "QL is too hard" | Start with built-in queries; custom queries can wait |
| "GitHub-only tool" | CLI works anywhere; GitHub integration is optional |
| "Semgrep covers the same" | CodeQL excels at deep interprocedural analysis Semgrep can't do |

## References

- Documentation: <https://codeql.github.com/docs/>
- Query Reference: <https://codeql.github.com/codeql-standard-libraries/>
- GitHub Repository: <https://github.com/github/codeql>
- Query Suites: <https://github.com/github/codeql/tree/main/misc/suite-helpers>
- VS Code Extension: <https://marketplace.visualstudio.com/items?itemName=GitHub.vscode-codeql>
- GitHub Actions: <https://github.com/github/codeql-action>
- SARIF Spec: <https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html>
- Learning Lab: <https://codeql.github.com/docs/writing-codeql-queries/introduction-to-ql/>
- Query Console: <https://github.com/github/codeql/discussions>
