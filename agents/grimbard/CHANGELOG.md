# Changelog

All notable changes to the Grimbard agent will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Additional language-specific workflows
- Integration with more SAST tools
- AI-assisted triage (experimental)
- Auto-remediation suggestions (experimental)
- SIEM integration support

## [1.0.0] - 2026-01-22

### Added

#### Agent Structure
- Complete agent distribution structure following AGENT.md standard
- Manifest file (AGENT.md) with metadata and commands
- Comprehensive user documentation (README.md)
- Configuration system with YAML files
- Modular workflow architecture

#### Workflows
- Complete 6-phase secure code review workflow
- Quick scan workflow for CI/CD (15-30 min)
- Vulnerability triage workflow for SARIF processing
- Compliance audit workflow (PCI-DSS, HIPAA, SOC2, GDPR)

#### Tool Integration
- Opengrep (Semgrep OSS fork) for pattern-based SAST
- Gitleaks for secrets detection
- KICS for IaC security (Terraform, K8s, Docker)
- Noir for API endpoint discovery
- OSV-Scanner for dependency vulnerability scanning
- Depscan for advanced SCA with SBOM/VDR
- Application Inspector for technology profiling
- SARIF Issue Reporter for findings analysis

#### Configuration
- agent-config.yml for high-level settings
- tools.yml for per-tool configurations
- permissions.yml for security controls
- Environment variable support

#### Documentation
- User guide (README.md)
- Workflow documentation  (workflows/README.md)
- Configuration guide (config/README.md)
- Report templates (templates/)
- Example projects (examples/)

#### Skills Included
- 8 static analysis tool skills:
  - semgrep - Pattern-based SAST
  - opengrep - Open source Semgrep fork
  - gitleaks - Secrets detection
  - kics - IaC security scanning
  - noir - API endpoint discovery
  - osv-scanner - Dependency vulnerability scanning
  - depscan - Advanced SCA with SBOM/VDR
  - application-inspector - Technology profiling
- sarif-issue-reporter - SARIF analysis and reporting
- 20+ security pattern skills
- 40+ security anti-pattern skills

#### Report Templates
- Executive summary template
- Technical findings template
- Compliance matrix template
- Finding detail template

#### Examples
- Node.js Express API security review
- Python Django application audit
- Terraform infrastructure assessment

### Changed
- Restructured agent/ directory for distribution
- Moved from monolithic workflow to modular approach
- Enhanced documentation and user guides

### Technical Details
- Claude Code version requirement: >=2.0.0
- Python version requirement: >=3.11
- Docker version requirement: >=20.0
- SARIF specification: v2.1.0
- Configuration format: YAML

## [0.1.0] - 2026-01-15

### Added
- Initial secure-code-review.md workflow
- Basic 6-phase security review process
- Tool command examples for baldwin.sh integration
- SARIF output guidance
- Manual review checklists

### Known Limitations
- Single monolithic workflow file
- No configuration system
- Limited documentation
- No modular approach

---

## Version History Summary

| Version | Date | Description |
|---------|------|-------------|
| 1.0.0 | 2026-01-22 | **Stable Release** - Complete distribution structure |
| 0.1.0 | 2026-01-15 | Initial workflow creation |

## Upgrade Guide

### From 0.1.0 to 1.0.0

**Breaking Changes:**
- Workflow location changed from root to `workflows/` directory
- Configuration now in YAML instead of hardcoded

**Migration Steps:**

1. Update skill installation:
```bash
npx skills add igbuend/grimbard@latest
```

2. Old workflow references need updating:
```bash
# Old (0.1.0)
agent/grimbard/secure-code-review.md

# New (1.0.0)
agent/grimbard/workflows/secure-code-review.md
```

3. Configuration now optional but recommended:
```bash
# Copy default config
cp agent/grimbard/config/agent-config.yml.example my-config.yml
# Edit and use
```

4. New command format:
```bash
# Old (0.1.0) - manual workflow loading
# No commands

# New (1.0.0) - built-in commands
/grimbard-review
/grimbard-quick
/grimbard-triage
/grimbard-compliance
```

## Future Roadmap

### Version 1.1.0 (Planned Q2 2026)
- Additional language-specific security workflows
- Enhanced compliance reporting
- Integration with issue trackers (GitHub Issues, JIRA)
- SIEM integration (Splunk, Elasticsearch)

### Version 1.2.0 (Planned Q3 2026)
- AI-assisted triage (experimental)
- Auto-remediation suggestions
- Custom rule generator
- Enhanced threat modeling

### Version 2.0.0 (Planned Q4 2026)
- Multi-agent orchestration
- Distributed scanning for large codebases
- Real-time collaboration features
- Cloud-native deployment options

---

For detailed information about each version, see the [GitHub Releases](https://github.com/igbuend/grimbard/releases) page.
