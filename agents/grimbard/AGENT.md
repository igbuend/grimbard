---
description: Security-focused code review agent documentation. See .claude-plugin/plugin.json for plugin configuration.
---

# Grimbard Security Review Agent

> Comprehensive AI-powered security code review combining automated static analysis with structured manual review workflows.

Named after the wise badger in Reynard the Fox who provides counsel and guidance.

## Overview

Grimbard provides systematic security code review workflows that combine:

- **Automated Analysis**: 8+ static analysis tools (Opengrep, Gitleaks, KICS, Noir, OSV-Scanner, Depscan, Application Inspector)
- **SARIF Integration**: Unified findings from all tools in standard format
- **Structured Workflows**: 6-phase comprehensive review process
- **Manual Review Guidance**: Checklists for authentication, authorization, cryptography, etc.
- **Professional Reporting**: Executive summaries, technical findings, remediation guidance

## Features

### Automated Security Scanning

- **Code Security**: Opengrep/Semgrep for pattern-based SAST
- **Secrets Detection**: Gitleaks for hardcoded credentials
- **IaC Security**: KICS for Terraform, Kubernetes, Docker
- **API Discovery**: Noir for attack surface mapping
- **Dependency Scanning**: OSV-Scanner and Depscan for SCA
- **Technology Profiling**: Application Inspector for feature analysis

### Structured Review Process

1. **Phase 1: Discovery** - Repository structure, attack surface, dependencies
2. **Phase 2: Automated Analysis** - All security scanning tools
3. **Phase 3: SARIF Triage** - Prioritization by severity and exploitability
4. **Phase 4: Manual Review** - Authentication, authorization, crypto, input validation
5. **Phase 5: Deep Dive** - Variant analysis, threat modeling
6. **Phase 6: Reporting** - Professional security assessment reports

### Compliance Support

Built-in workflows for:
- PCI-DSS payment card compliance
- HIPAA healthcare data protection
- SOC 2 security controls
- GDPR data protection requirements

## Quick Start

### Run Complete Security Review

```bash
# Navigate to your project
cd /path/to/your/project

# Run full 6-phase review
/grimbard-review .
```

**Duration**: 4-8 hours (varies by codebase size)

**Output**:
```
security-review-output/
├── sarif/              # All SARIF files from tools
├── reports/            # Generated reports
│   ├── executive-summary.md
│   ├── technical-findings.md
│   └── report.html
└── findings/           # Individual finding details
```

### Quick Automated Scan

```bash
# Fast feedback for CI/CD (15-30 min)
/grimbard-quick /path/to/project
```

### Triage Existing SARIF Files

```bash
# Prioritize findings from existing scans
/grimbard-triage ./sarif-results/
```

### Compliance Audit

```bash
# PCI-DSS, HIPAA, SOC2, GDPR focused review
/grimbard-compliance /path/to/project
```

## Workflows

### 1. Secure Code Review (Complete)

**File**: `workflows/secure-code-review.md`

**Use when**: Comprehensive security audit needed

**Duration**: 4-8 hours

**Phases**:
1. Initial Discovery & Reconnaissance
2. Automated Static Analysis
3. SARIF Triage & Prioritization
4. Deep Manual Review
5. Iterative Deepening
6. Reporting

**Output**: Complete security assessment report

### 2. Quick Scan

**File**: `workflows/quick-scan.md`

**Use when**: Fast feedback in CI/CD or pre-commit

**Duration**: 15-30 minutes

**Phases**: 1-3 only (automated tools + triage)

**Output**: Automated findings with priority levels

### 3. Vulnerability Triage

**File**: `workflows/vulnerability-triage.md`

**Use when**: Multiple SARIF files need prioritization

**Duration**: 30-60 minutes

**Output**: Prioritized findings list with remediation plan

### 4. Compliance Audit

**File**: `workflows/compliance-audit.md`

**Use when**: PCI-DSS, HIPAA, SOC2, GDPR compliance needed

**Duration**: 6-10 hours

**Output**: Compliance-focused assessment with framework mappings

## Configuration

Grimbard can be customized via YAML configuration files:

### Agent Configuration

**File**: `config/agent-config.yml`

Configure:
- Default workflows
- Enabled tools
- Output formats and directories
- Severity thresholds
- Report templates
- Performance settings

### Tool Settings

**File**: `config/tools.yml`

Configure per-tool:
- Command-line flags
- Rule sets
- Exclusions
- Severity filters
- Output formats

### Permissions

**File**: `config/permissions.yml`

Security controls:
- Filesystem access restrictions
- Network access controls
- Allowed/blocked commands
- Environment variable access
- Process limits

## Environment Variables

```bash
# Output directory (default: ./grimbard-security-review)
export GRIMBARD_OUTPUT_DIR=./custom-output

# Tool configuration directory
export GRIMBARD_CONFIG_DIR=./custom-config

# Report formats (comma-separated)
export GRIMBARD_REPORTS_FORMAT=markdown,sarif,html

# Severity threshold (error, warning, note, info)
export GRIMBARD_SEVERITY_THRESHOLD=warning
```

## Tool Integration

All tools output SARIF v2.1.0 for unified processing:

| Tool | Purpose | SARIF Output |
|------|---------|--------------|
| **Opengrep** | Code patterns, vulnerabilities | ✓ |
| **Gitleaks** | Hardcoded secrets | ✓ |
| **KICS** | IaC security (Terraform, K8s, Docker) | ✓ |
| **Noir** | API endpoints, attack surface | ✓ |
| **OSV-Scanner** | Dependency vulnerabilities | ✓ |
| **Depscan** | Advanced SCA, SBOM, VDR | ✓ |
| **Application Inspector** | Technology profiling | ✓ |

## Requirements

### Required

- Claude Code 2.0+
- Python 3.11+
- Docker 20.0+ (for containerized tools)
- Git

### Skills Required

All grimbard skills must be installed:

```bash
# Install all skills
npx add-skill igbuend/grimbard
```

This installs:
- Static analysis tool skills (8 tools)
- SARIF Issue Reporter skill
- Security pattern skills
- Security anti-pattern skills

### Optional Tools

- **CodeQL** - For deep cross-file analysis

## Documentation

- [User Guide](README.md) - Complete usage documentation
- [Workflows](workflows/README.md) - Detailed workflow descriptions
- [Configuration](config/README.md) - Configuration guide
- [Templates](templates/README.md) - Report template customization

## Supported Languages

Via Opengrep/Semgrep (30+ languages):

- **Web**: JavaScript, TypeScript, JSX, TSX, HTML
- **Backend**: Python, Go, Java, Kotlin, Scala, C#
- **Systems**: C, C++, Rust
- **Mobile**: Swift, Kotlin, Java, Objective-C
- **Scripting**: Ruby, PHP, Bash, Lua, Perl
- **Infrastructure**: Terraform, Dockerfile, YAML, JSON
- **Other**: Solidity, Elixir, Clojure, Apex, R

## Support

- **Issues**: https://github.com/igbuend/grimbard/issues
- **Discussions**: https://github.com/igbuend/grimbard/discussions
- **Ko-fi**: https://ko-fi.com/igbuend

## License

MIT License - See [LICENSE](../../LICENSE)

## Credits

- Skills derived from [Trail of Bits Skills Marketplace](https://github.com/trailofbits/skills)
- Inspired by [baldwin.sh](https://github.com/igbuend/baldwin.sh)
- Security patterns from [DistriNet Research](https://securitypatterns.distrinet-research.be/)
- Named after Grimbard the Badger from Reynard the Fox
