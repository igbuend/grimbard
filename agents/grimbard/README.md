# Grimbard Security Review Agent

> Comprehensive AI-powered security code review combining automated static analysis with structured manual review workflows.

**Named after the wise badger in Reynard the Fox who provides counsel and guidance.**

## What is Grimbard?

Grimbard is a security-focused agent for Claude Code that automates vulnerability detection, guides manual security analysis, and generates professional security reports. It combines 8+ static analysis tools with systematic manual review workflows to provide comprehensive security assessments.

## Key Features

- **8+ Security Tools**: Opengrep, Gitleaks, KICS, Noir, OSV-Scanner, Depscan, Application Inspector
- **SARIF Integration**: Unified findings format from all tools
- **Structured Workflows**: 6-phase comprehensive review process
- **Multiple Use Cases**: Complete audit, quick scan, triage, compliance
- **Professional Reports**: Executive summaries, technical findings, remediation guidance
- **Compliance Support**: PCI-DSS, HIPAA, SOC2, GDPR focused reviews

## Quick Start

### Installation

```bash
# Install via NPM (recommended)
npx skills add igbuend/grimbard

# Or install from source
git clone https://github.com/igbuend/grimbard.git
cd grimbard
npx skills add .
```

### Run Your First Security Review

```bash
# Navigate to your project
cd /path/to/your/project

# Run complete security review (4-8 hours)
/grimbard-review .

# Or quick scan only (15-30 min)
/grimbard-quick .
```

## Available Commands

| Command | Purpose | Duration | Phases |
|---------|---------|----------|--------|
| `/grimbard-review` | Complete security audit | 4-8 hours | All 6 phases |
| `/grimbard-quick` | Automated scan only | 15-30 min | Phases 1-3 |
| `/grimbard-triage` | Prioritize SARIF findings | 30-60 min | Phase 3 only |
| `/grimbard-compliance` | Compliance audit | 6-10 hours | Compliance-focused |

## Workflows

### 1. Complete Security Review

**Perfect for**: Comprehensive security audits, pre-release assessments

**Includes**:
- Repository structure analysis
- Attack surface mapping with Noir
- Automated security scanning (all 8 tools)
- SARIF findings triage and prioritization
- Manual review of auth, authorization, crypto, input validation
- Variant analysis and threat modeling
- Professional report generation

**Output**: Complete security assessment with executive summary

### 2. Quick Scan

**Perfect for**: CI/CD pipelines, pre-commit checks, fast feedback

**Includes**:
- Discovery phase
- Automated tool scanning only
- Basic triage

**Output**: Prioritized vulnerability list

### 3. Vulnerability Triage

**Perfect for**: When you have existing SARIF files from multiple tools

**Includes**:
- SARIF aggregation
- Severity-based prioritization
- False positive filtering

**Output**: Prioritized backlog for manual review

### 4. Compliance Audit

**Perfect for**: PCI-DSS, HIPAA, SOC2, GDPR compliance requirements

**Includes**:
- Framework-specific controls review
- Compliance checklist mapping
- Gap analysis

**Output**: Compliance-focused assessment report

## Configuration

### Basic Configuration

Edit `config/agent-config.yml`:

```yaml
workflows:
  default: secure-code-review

tools:
  enabled-by-default:
    - opengrep
    - gitleaks
    - kics
    - osv-scanner

output:
  formats: [sarif, markdown, html]
  directory: ./security-review-output
```

### Tool-Specific Settings

Edit `config/tools.yml` to customize:
- Command-line flags
- Rule sets
- Exclusions
- Severity filters

### Security Permissions

Edit `config/permissions.yml` to control:
- Filesystem access
- Network access
- Allowed commands
- Resource limits

See [Configuration Guide](config/README.md) for details.

## Output Structure

```
security-review-output/
├── sarif/
│   ├── opengrep.sarif
│   ├── gitleaks.sarif
│   ├── kics.sarif
│   ├── noir.sarif
│   ├── osv-scanner.sarif
│   └── consolidated.sarif
├── reports/
│   ├── executive-summary.md
│   ├── technical-findings.md
│   ├── compliance-matrix.md
│   └── report.html
└── findings/
    ├── P0-critical/
    ├── P1-high/
    ├── P2-medium/
    └── P3-low/
```

## Tool Integration

All tools output SARIF v2.1.0:

- **Opengrep** - Pattern-based SAST (30+ languages)
- **Gitleaks** - Secrets and credentials detection
- **KICS** - Infrastructure as Code security (Terraform, K8s, Docker)
- **Noir** - API endpoint discovery and attack surface
- **OSV-Scanner** - Dependency vulnerability scanning
- **Depscan** - Advanced SCA with SBOM and VDR
- **Application Inspector** - Technology and security feature profiling

## Examples

### Example 1: Node.js Express API

```bash
cd examples/nodejs-express-api
/grimbard-review .
```

**Typical Findings**: SQL injection, XSS, missing authentication, weak session management

### Example 2: Python Django Application

```bash
cd examples/python-django-app
/grimbard-review .
```

**Typical Findings**: CSRF issues, insecure deserialization, weak password hashing

### Example 3: Terraform Infrastructure

```bash
cd examples/terraform-infrastructure
/grimbard-review .
```

**Typical Findings**: Open S3 buckets, overly permissive security groups, missing encryption

See [Examples Guide](examples/README.md) for detailed walkthroughs.

## Customization

### Custom Workflows

Create new workflows by copying and modifying existing ones:

```bash
cp workflows/secure-code-review.md workflows/my-custom-workflow.md
# Edit the workflow
# Add to AGENT.md commands section
```

### Custom Report Templates

```bash
# Add template
cp templates/technical-report.md templates/my-template.md

# Reference in workflow Phase 6
```

### Custom Tool Configurations

```yaml
# config/tools.yml
my-custom-tool:
  enabled: true
  flags: [--custom-option]
  output:
    format: sarif
    file: my-tool.sarif
```

## Requirements

### Minimum Requirements

- **Claude Code**: 2.0 or higher
- **Python**: 3.11 or higher
- **Docker**: 20.0 or higher (for containerized tools)
- **Git**: Any recent version
- **RAM**: 8GB recommended for large codebases
- **Disk**: 10GB free for tool outputs

### Skills Installation

All grimbard skills must be installed:

```bash
npx skills add igbuend/grimbard
```

This includes:
- 8 static analysis tool skills
- SARIF Issue Reporter skill
- Security pattern skills (20+)
- Security anti-pattern skills (40+)

## Troubleshooting

### Tool Not Found

```bash
# Install missing tools
pip install semgrep gitleaks
brew install kics noir
go install github.com/google/osv-scanner/cmd/osv-scanner@latest
```

### Permission Denied

Check `config/permissions.yml` - ensure tool is in allowed commands list.

### SARIF Invalid

```bash
# Validate SARIF files
pip install sarif-tools
sarif validate results.sarif
```

### Out of Memory

For large codebases, run tools individually:

```bash
/grimbard-quick --tool=opengrep
/grimbard-quick --tool=gitleaks
# etc.
```

## FAQ

**Q: How long does a complete review take?**
A: 4-8 hours depending on codebase size. Quick scan takes 15-30 minutes.

**Q: Can I use only specific tools?**
A: Yes, configure `config/agent-config.yml` to enable/disable tools.

**Q: Does it work with monorepos?**
A: Yes, but consider running per-service for better results.

**Q: Can I run in CI/CD?**
A: Yes, use `/grimbard-quick` for fast automated feedback.

**Q: What languages are supported?**
A: 30+ languages via Opengrep/Semgrep. See [AGENT.md](AGENT.md) for full list.

**Q: How do I report false positives?**
A: Document during Phase 3 triage. Use inline suppressions (`# nosemgrep:`) in code.

**Q: Can I customize report templates?**
A: Yes, see `templates/` directory and [Templates Guide](templates/README.md).

**Q: Is Semgrep Pro required?**
A: No, Opengrep (open source fork) is used by default. Semgrep Pro is optional.

## Documentation

- **[AGENT.md](AGENT.md)** - Agent manifest and overview
- **[Workflows](workflows/README.md)** - Detailed workflow documentation
- **[Configuration](config/README.md)** - Configuration guide
- **[Templates](templates/README.md)** - Report template customization
- **[Examples](examples/README.md)** - Example usage and outputs
- **[CHANGELOG.md](CHANGELOG.md)** - Version history

## Contributing

See [CONTRIBUTING.md](../../CONTRIBUTING.md) in main repository.

## Support

- **Issues**: https://github.com/igbuend/grimbard/issues
- **Discussions**: https://github.com/igbuend/grimbard/discussions
- **Ko-fi**: https://ko-fi.com/igbuend

## License

MIT License - See [LICENSE](../../LICENSE)

## Credits

- Skills from [Trail of Bits Skills Marketplace](https://github.com/trailofbits/skills)
- Inspired by [baldwin.sh](https://github.com/igbuend/baldwin.sh)
- Security patterns from [DistriNet Research](https://securitypatterns.distrinet-research.be/)
- Named after Grimbard the Badger from medieval fable Reynard the Fox

## Disclaimer

No AIs were harmed during the creation of this agent.
