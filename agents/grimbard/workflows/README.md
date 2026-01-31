# Grimbard Workflows

This directory contains structured security review workflows for the Grimbard agent.

## Available Workflows

### 1. Complete Security Review

**File**: `secure-code-review.md`
**Command**: `/grimbard-review`
**Duration**: 4-8 hours
**Use When**: Comprehensive security audit needed

**Phases**:
1. **Discovery & Reconnaissance** - Repository structure, attack surface, dependencies
2. **Automated Static Analysis** - All 8 security tools
3. **SARIF Triage & Prioritization** - Severity-based ranking, false positive filtering
4. **Deep Manual Review** - Authentication, authorization, crypto, input validation
5. **Iterative Deepening** - Variant analysis, threat modeling
6. **Reporting** - Executive summary, technical findings, remediation guidance

**Output**:
- Complete security assessment report
- SARIF files from all tools
- Prioritized vulnerability backlog
- Remediation recommendations

---

### 2. Quick Scan

**File**: `quick-scan.md`
**Command**: `/grimbard-quick`
**Duration**: 15-30 minutes
**Use When**: Fast feedback needed (CI/CD, pre-commit)

**Phases**: 1-3 only (Discovery, Automated Analysis, Triage)

**Output**:
- Automated findings from all tools
- Basic prioritization
- SARIF consolidated report

**Perfect for**:
- CI/CD pipeline integration
- Pre-commit hooks
- Developer quick checks
- Initial vulnerability assessment

---

### 3. Vulnerability Triage

**File**: `vulnerability-triage.md`
**Command**: `/grimbard-triage`
**Duration**: 30-60 minutes
**Use When**: Existing SARIF files need prioritization

**What It Does**:
- Aggregates multiple SARIF files
- Applies severity-based ranking
- Filters false positives
- Creates actionable backlog

**Input**: Directory containing SARIF files from previous scans

**Output**:
- Prioritized findings list (P0-P3)
- Consolidated SARIF report
- Remediation plan

**Perfect for**:
- Processing historical scan results
- Merging findings from multiple tools
- Creating sprint backlogs
- Security debt tracking

---

### 4. Compliance Audit

**File**: `compliance-audit.md`
**Command**: `/grimbard-compliance`
**Duration**: 6-10 hours
**Use When**: Compliance requirements must be validated

**Supported Frameworks**:
- **PCI-DSS** - Payment Card Industry Data Security Standard
- **HIPAA** - Health Insurance Portability and Accountability Act
- **SOC 2** - System and Organization Controls
- **GDPR** - General Data Protection Regulation

**What It Does**:
- Maps findings to compliance controls
- Validates framework-specific requirements
- Identifies compliance gaps
- Generates audit-ready reports

**Output**:
- Compliance matrix (requirements → findings)
- Gap analysis
- Remediation roadmap
- Audit-ready documentation

**Perfect for**:
- Pre-audit preparation
- Continuous compliance monitoring
- Certification requirements
- Regulatory assessments

---

## Workflow Selection Guide

| Scenario | Recommended Workflow | Duration |
|----------|---------------------|----------|
| Pre-release security audit | Complete Security Review | 4-8 hours |
| CI/CD integration | Quick Scan | 15-30 min |
| Sprint planning | Vulnerability Triage | 30-60 min |
| Compliance certification | Compliance Audit | 6-10 hours |
| Daily development | Quick Scan | 15-30 min |
| Quarterly security review | Complete Security Review | 4-8 hours |
| Processing old scan data | Vulnerability Triage | 30-60 min |
| SOC 2 Type II audit prep | Compliance Audit | 6-10 hours |

## Common Workflow Patterns

### Pattern 1: Continuous Security

```bash
# Daily: Quick scans in CI/CD
/grimbard-quick /path/to/project

# Weekly: Triage accumulated findings
/grimbard-triage ./sarif-results/

# Quarterly: Complete review
/grimbard-review /path/to/project
```

### Pattern 2: Compliance-Driven

```bash
# Initial assessment
/grimbard-review /path/to/project

# Ongoing compliance monitoring
/grimbard-compliance /path/to/project

# Pre-audit validation
/grimbard-compliance /path/to/project
```

### Pattern 3: Remediation Workflow

```bash
# 1. Identify issues
/grimbard-review /path/to/project

# 2. Prioritize backlog
/grimbard-triage ./security-review-output/sarif/

# 3. Validate fixes (quick scan after remediation)
/grimbard-quick /path/to/project

# 4. Final verification
/grimbard-review /path/to/project
```

## Output Structure

All workflows produce standardized output:

```
security-review-output/
├── sarif/
│   ├── opengrep.sarif
│   ├── gitleaks.sarif
│   ├── kics.sarif
│   ├── noir.sarif
│   ├── osv-scanner.sarif
│   ├── depscan.sarif
│   ├── application-inspector.sarif
│   └── consolidated.sarif
├── reports/
│   ├── executive-summary.md
│   ├── technical-findings.md
│   ├── compliance-matrix.md      # Compliance audit only
│   └── report.html
└── findings/
    ├── P0-critical/
    ├── P1-high/
    ├── P2-medium/
    └── P3-low/
```

## Customizing Workflows

### Create Custom Workflow

1. Copy existing workflow as template:
   ```bash
   cp workflows/secure-code-review.md workflows/my-custom-workflow.md
   ```

2. Modify phases and tools as needed

3. Add command to `AGENT.md`:
   ```yaml
   commands:
     - name: grimbard-custom
       description: My custom workflow
       workflow: workflows/my-custom-workflow.md
   ```

### Modify Existing Workflow

Workflows are markdown files that can be edited directly. Each workflow includes:

- **Phase definitions** - What happens in each phase
- **Tool commands** - Specific commands to run
- **Checklist items** - Manual review items
- **Output expectations** - What should be produced

## Workflow Configuration

Workflows can be configured via `config/agent-config.yml`:

```yaml
workflows:
  default: secure-code-review

  settings:
    parallel-tool-execution: true
    continue-on-tool-failure: true
    max-tool-runtime: 3600  # 1 hour per tool

output:
  directory: ./security-review-output
  formats: [sarif, markdown, html]

tools:
  enabled-by-default:
    - opengrep
    - gitleaks
    - kics
    - osv-scanner
```

## Tool Integration

All workflows leverage these tools:

| Tool | Purpose | Output |
|------|---------|--------|
| **Opengrep** | Pattern-based SAST | SARIF |
| **Gitleaks** | Secrets detection | SARIF |
| **KICS** | IaC security (Terraform, K8s, Docker) | SARIF |
| **Noir** | API endpoint discovery | SARIF |
| **OSV-Scanner** | Dependency vulnerabilities | SARIF |
| **Depscan** | Advanced SCA, SBOM, VDR | SARIF |
| **Application Inspector** | Technology profiling | SARIF |

## Performance Considerations

### Large Codebases (>100K LOC)

- Use Quick Scan first to identify tool-specific issues
- Run tools individually if memory constrained
- Consider excluding generated code and dependencies
- Use `.agentignore` to skip unnecessary files

### CI/CD Integration

- Quick Scan workflow is optimized for CI/CD (15-30 min)
- Configure failure thresholds in `config/agent-config.yml`
- Use caching for dependency scans
- Consider running full review nightly instead of per-commit

### Resource Limits

Default limits (configurable in `config/permissions.yml`):

- **Memory**: 8GB recommended
- **Disk**: 10GB for tool outputs
- **CPU**: Parallel execution scales with cores
- **Network**: Required for OSV-Scanner and Depscan

## Troubleshooting

### Workflow Stuck

```bash
# Check running processes
ps aux | grep -E "semgrep|opengrep|gitleaks|kics|noir|osv-scanner|depscan"

# Check logs
tail -f security-review-output/logs/workflow.log
```

### Tool Failures

Most workflows continue on tool failure by default. Check:

```bash
# Individual tool logs
ls security-review-output/logs/

# SARIF output presence
ls security-review-output/sarif/
```

### Out of Memory

```bash
# Run tools individually
/grimbard-quick --tool=opengrep
/grimbard-quick --tool=gitleaks
# etc.

# Or reduce scope
/grimbard-review ./specific-subdirectory
```

## References

- [SARIF Specification v2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [OWASP SAST Guide](https://owasp.org/www-community/Source_Code_Analysis_Tools)
- [NIST SSDF](https://csrc.nist.gov/publications/detail/sp/800-218/final)
- [Trail of Bits Security Guide](https://github.com/trailofbits/testing-handbook)

## Support

For issues with workflows:

- **GitHub Issues**: https://github.com/igbuend/grimbard/issues
- **Discussions**: https://github.com/igbuend/grimbard/discussions
