# Grimbard Configuration

This directory contains configuration files for customizing Grimbard's behavior, tool settings, and security policies.

## Configuration Files

### 1. `agent-config.yml`

**Purpose**: High-level agent configuration and workflow settings

**Location**: `config/agent-config.yml`

**Contains**:
- Default workflow selection
- Enabled tools
- Output formats and directories
- Severity thresholds
- Report templates
- Performance settings

**Example**:
```yaml
agent:
  name: grimbard
  version: 1.0.0

workflows:
  default: secure-code-review

  settings:
    parallel-tool-execution: true
    continue-on-tool-failure: true
    max-tool-runtime: 3600  # seconds (1 hour)
    timeout-on-failure: false

tools:
  enabled-by-default:
    - opengrep
    - gitleaks
    - kics
    - osv-scanner
    - depscan

  disabled-by-default:
    - noir  # Enable only when API scanning needed
    - application-inspector  # Enable for tech profiling

output:
  directory: ./security-review-output

  formats:
    - sarif
    - markdown
    - html

  sarif:
    version: "2.1.0"
    consolidate: true

  reports:
    executive-summary: true
    technical-findings: true
    compliance-matrix: false  # Enable for compliance audits

severity:
  threshold: warning  # error, warning, note, info

  fail-on:
    - error

  priority-matrix:
    error-high-exploitability: P0
    error-medium-exploitability: P1
    warning-high-exploitability: P1
    warning-medium-exploitability: P2
    note: P3
    info: P3

performance:
  max-parallel-tools: 4
  memory-limit-mb: 8192
  disk-space-gb: 10
```

---

### 2. `tools.yml`

**Purpose**: Per-tool configuration, command-line flags, and rule sets

**Location**: `config/tools.yml`

**Contains**:
- Tool-specific command-line arguments
- Rule set selections
- File/path exclusions
- Output configurations
- Severity filters

**Example**:
```yaml
opengrep:
  enabled: true

  command: opengrep

  flags:
    - --config=auto
    - --sarif
    - --quiet
    - --max-memory=4096

  rules:
    - p/security-audit
    - p/owasp-top-ten
    - p/cwe-top-25

  exclude:
    - "test/**"
    - "tests/**"
    - "**/*_test.go"
    - "**/*_spec.rb"
    - "**/node_modules/**"
    - "**/vendor/**"
    - "**/.git/**"

  severity-filter: warning  # only warning and above

  output:
    format: sarif
    file: opengrep.sarif

gitleaks:
  enabled: true

  command: gitleaks

  flags:
    - detect
    - --no-banner
    - --no-color
    - --redact
    - --exit-code=0  # don't fail on findings

  config-file: .gitleaks.toml  # optional custom config

  output:
    format: sarif
    file: gitleaks.sarif

kics:
  enabled: true

  command: kics

  flags:
    - scan
    - --exclude-paths=node_modules,vendor,.git
    - --exclude-severities=info

  platforms:
    - Terraform
    - Kubernetes
    - Docker
    - CloudFormation

  output:
    formats: [sarif]
    path: kics.sarif

noir:
  enabled: false  # Enable manually when needed

  command: noir

  flags:
    - -b  # base path
    - --format=sarif

  output:
    file: noir.sarif

osv-scanner:
  enabled: true

  command: osv-scanner

  flags:
    - scan
    - --format=sarif
    - --call-analysis=all

  lockfiles:
    - package-lock.json
    - yarn.lock
    - go.sum
    - Cargo.lock
    - requirements.txt
    - Pipfile.lock

  output:
    file: osv-scanner.sarif

depscan:
  enabled: true

  command: depscan

  flags:
    - --no-banner
    - --no-error
    - --suggest

  reports:
    - sarif
    - html

  output:
    dir: ./depscan-output
    sarif-file: depscan.sarif

application-inspector:
  enabled: false

  command: appinspector

  flags:
    - analyze
    - --output-file-format=sarif

  output:
    file: app-inspector.sarif
```

---

### 3. `permissions.yml`

**Purpose**: Security controls and resource limits for agent execution

**Location**: `config/permissions.yml`

**Contains**:
- Filesystem access restrictions
- Network access controls
- Allowed/blocked commands
- Environment variable access
- Resource limits

**Example**:
```yaml
filesystem:
  allowed-paths:
    - .  # Current directory and subdirectories
    - /tmp  # Temp directory for tool outputs

  blocked-paths:
    - /etc
    - /var
    - ~/.ssh
    - ~/.aws
    - ~/.gcp

  read-only-paths:
    - /usr
    - /opt

  writable-paths:
    - ./security-review-output
    - ./vulnerability-triage
    - ./compliance-audit
    - /tmp

network:
  allow-internet: true  # Required for OSV-Scanner, Depscan

  allowed-domains:
    - api.osv.dev  # OSV-Scanner
    - osv-vulnerabilities.storage.googleapis.com  # OSV-Scanner
    - github.com  # Depscan, rule updates
    - owasp.org  # Depscan

  blocked-domains:
    - "*"  # Block all others by default

commands:
  allowed:
    - semgrep
    - opengrep
    - gitleaks
    - kics
    - noir
    - osv-scanner
    - depscan
    - appinspector
    - python
    - python3
    - pip
    - git
    - find
    - grep
    - jq
    - cat
    - ls
    - mkdir
    - cp

  blocked:
    - rm -rf  # Prevent destructive operations
    - dd
    - mkfs
    - fdisk
    - systemctl
    - service
    - shutdown
    - reboot

environment:
  allowed-vars:
    - GRIMBARD_OUTPUT_DIR
    - GRIMBARD_CONFIG_DIR
    - GRIMBARD_REPORTS_FORMAT
    - GRIMBARD_SEVERITY_THRESHOLD
    - HOME
    - PATH
    - TMPDIR

  blocked-vars:
    - AWS_SECRET_ACCESS_KEY
    - GITHUB_TOKEN
    - SLACK_TOKEN

resources:
  max-processes: 10
  max-memory-mb: 8192
  max-disk-gb: 10
  max-cpu-percent: 80
  timeout-seconds: 14400  # 4 hours for complete review
```

---

## Configuration Precedence

Configurations are applied in this order (later overrides earlier):

1. **Default values** (built-in)
2. **config/agent-config.yml** (high-level settings)
3. **config/tools.yml** (tool-specific settings)
4. **config/permissions.yml** (security constraints)
5. **Environment variables** (runtime overrides)
6. **Command-line flags** (highest priority)

## Environment Variables

Environment variables override configuration files:

```bash
# Output directory
export GRIMBARD_OUTPUT_DIR=./custom-output

# Config directory
export GRIMBARD_CONFIG_DIR=./custom-config

# Report formats (comma-separated)
export GRIMBARD_REPORTS_FORMAT=markdown,sarif,html

# Severity threshold
export GRIMBARD_SEVERITY_THRESHOLD=warning

# Enable specific tools (comma-separated)
export GRIMBARD_ENABLED_TOOLS=opengrep,gitleaks,kics

# Parallel execution
export GRIMBARD_PARALLEL_EXECUTION=true

# Timeout (seconds)
export GRIMBARD_TIMEOUT=7200
```

## Configuration Examples

### Example 1: CI/CD Quick Scan Configuration

**Use Case**: Fast scans in CI/CD pipelines

```yaml
# config/ci-config.yml
workflows:
  default: quick-scan

tools:
  enabled-by-default:
    - opengrep
    - gitleaks
    - osv-scanner

output:
  formats: [sarif]
  directory: ./ci-scan-results

severity:
  threshold: error
  fail-on: [error]

performance:
  max-tool-runtime: 600  # 10 minutes
  timeout-on-failure: true
```

**Usage**:
```bash
GRIMBARD_CONFIG_DIR=./config /grimbard-quick .
```

---

### Example 2: Compliance Audit Configuration

**Use Case**: PCI-DSS compliance audit

```yaml
# config/pci-config.yml
workflows:
  default: compliance-audit

tools:
  enabled-by-default:
    - opengrep
    - gitleaks
    - kics
    - osv-scanner
    - depscan
    - application-inspector

opengrep:
  rules:
    - p/pci-dss
    - p/security-audit
    - p/secrets

output:
  formats: [sarif, markdown, html]
  reports:
    executive-summary: true
    technical-findings: true
    compliance-matrix: true

severity:
  threshold: note  # Include all findings for compliance
```

---

### Example 3: Performance-Optimized Configuration

**Use Case**: Large codebase (>500K LOC)

```yaml
# config/performance-config.yml
workflows:
  settings:
    parallel-tool-execution: true
    max-tool-runtime: 7200  # 2 hours per tool

tools:
  enabled-by-default:
    - opengrep
    - gitleaks
    - osv-scanner

opengrep:
  flags:
    - --max-memory=8192
    - --jobs=8
    - --timeout=7200

  exclude:
    - "**/node_modules/**"
    - "**/vendor/**"
    - "**/dist/**"
    - "**/build/**"

performance:
  max-parallel-tools: 2  # Limit for memory constraints
  memory-limit-mb: 16384
```

---

### Example 4: Strict Security Configuration

**Use Case**: Highly restricted environment

```yaml
# config/strict-config.yml
permissions:
  filesystem:
    allowed-paths:
      - .
    blocked-paths:
      - /etc
      - /var
      - /home

  network:
    allow-internet: false  # No network access

  commands:
    allowed:
      - opengrep
      - gitleaks
      - grep
      - find

  resources:
    max-processes: 4
    max-memory-mb: 4096
    max-cpu-percent: 50
```

---

## Custom Rule Sets

### Creating Custom Opengrep Rules

```yaml
# config/custom-rules.yml
opengrep:
  custom-rules:
    - name: custom-sql-injection
      pattern: |
        $QUERY = "SELECT * FROM " + $INPUT
      message: Potential SQL injection via string concatenation
      severity: ERROR
      languages: [javascript, python, java]

    - name: custom-hardcoded-secret
      pattern: |
        $VAR = "sk_live_..."
      message: Hardcoded Stripe API key detected
      severity: ERROR
      languages: [javascript, python]
```

---

## Tool-Specific Configurations

### Gitleaks Custom Config

Create `.gitleaks.toml` in project root:

```toml
# .gitleaks.toml
[allowlist]
paths = [
  ".*_test.go",
  ".*_spec.rb",
  "test/fixtures/"
]

regexes = [
  "example.com",
  "localhost"
]

[rules]
[[rules]]
id = "stripe-api-key"
description = "Stripe API Key"
regex = '''sk_(test|live)_[0-9a-zA-Z]{24}'''
```

### KICS Custom Query

```yaml
# config/kics-custom-queries.yaml
queries:
  - name: custom-s3-encryption
    severity: HIGH
    platform: Terraform
    query: |
      # Check S3 bucket encryption
```

---

## Validation

### Validate Configuration Files

```bash
# Validate YAML syntax
python3 -c "import yaml; yaml.safe_load(open('config/agent-config.yml'))"

# Validate against schema (if available)
# jsonschema -i config/agent-config.yml schema/agent-config.schema.json
```

### Test Configuration

```bash
# Dry run with configuration
/grimbard-review --config=./config/agent-config.yml --dry-run .

# Verify tool flags
/grimbard-review --config=./config/tools.yml --show-commands .
```

---

## Troubleshooting

### Configuration Not Applied

```bash
# Check configuration precedence
echo $GRIMBARD_CONFIG_DIR

# Verify file path
ls -la config/agent-config.yml

# Check YAML syntax errors
yamllint config/*.yml
```

### Tool Not Running

```bash
# Check if tool is enabled
grep -A5 "^toolname:" config/tools.yml

# Verify command exists
which opengrep gitleaks kics

# Check permissions
cat config/permissions.yml | grep -A10 "commands:"
```

### Permission Denied

```bash
# Review filesystem permissions
cat config/permissions.yml | grep -A10 "filesystem:"

# Check if path is allowed
# Ensure output directory is in writable-paths
```

---

## Best Practices

### 1. Version Control

```bash
# Track configuration in git
git add config/*.yml

# Don't commit sensitive data
echo "config/*-secret.yml" >> .gitignore
```

### 2. Environment-Specific Configs

```bash
config/
├── agent-config.yml          # Base config
├── agent-config.dev.yml      # Development overrides
├── agent-config.ci.yml       # CI/CD overrides
├── agent-config.prod.yml     # Production overrides
└── README.md

# Usage
export GRIMBARD_CONFIG=./config/agent-config.ci.yml
```

### 3. Document Customizations

Always add comments explaining why:

```yaml
opengrep:
  exclude:
    - "legacy/**"  # Deprecated code, not in active development
    - "vendor/**"  # Third-party code, scanned separately
```

### 4. Regular Reviews

Review and update configurations:
- After tool updates
- When adding new projects
- After security incidents
- Quarterly as best practice

---

## References

- [YAML Specification](https://yaml.org/spec/)
- [Opengrep Configuration](https://semgrep.dev/docs/running-rules/)
- [Gitleaks Configuration](https://github.com/gitleaks/gitleaks#configuration)
- [KICS Configuration](https://docs.kics.io/latest/configuration/)
- [SARIF Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/)

---

## Support

For configuration issues:
- **GitHub Issues**: https://github.com/igbuend/grimbard/issues
- **Discussions**: https://github.com/igbuend/grimbard/discussions
