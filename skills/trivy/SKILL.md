---
name: trivy
description: Run Aqua Trivy for comprehensive security scanning of containers, filesystems, git repos, and IaC. Use when scanning container images, detecting vulnerabilities, secrets, misconfigurations, or generating SBOMs.
allowed-tools:
  - Bash
  - Read
  - Glob
  - Grep
---

# Aqua Trivy - Comprehensive Security Scanner

## When to Use Trivy

**Ideal scenarios:**

- Container image vulnerability scanning
- Filesystem and repository scanning
- Infrastructure-as-Code (IaC) misconfiguration detection
- Secrets detection in code and images
- Software Bill of Materials (SBOM) generation
- License compliance checking
- Kubernetes cluster security assessment
- CI/CD security gates

**Complements other tools:**

- Use alongside Semgrep/CodeQL for application code analysis
- Combine with KICS for additional IaC coverage
- Use with Gitleaks for dedicated secrets scanning
- Pair with OSV-Scanner/Depscan for enhanced SCA

## When NOT to Use

Do NOT use this skill for:

- Deep application code vulnerability analysis (use Semgrep or CodeQL)
- API endpoint discovery (use Noir)
- Advanced SAST with taint tracking (use CodeQL)
- Penetration testing (use specialized tools)

## Installation

### Homebrew (Recommended for macOS/Linux)

```bash
# macOS and Linux (preferred method)
brew install trivy

# Verify installation
trivy --version
```

### Other Installation Methods

```bash
# Docker
docker pull aquasec/trivy:latest

# Install script (Linux/macOS)
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# apt (Debian/Ubuntu)
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy

# yum/dnf (RHEL/CentOS/Fedora)
sudo rpm -ivh https://github.com/aquasecurity/trivy/releases/latest/download/trivy_*_Linux-64bit.rpm

# Windows (Chocolatey)
choco install trivy

# Windows (Scoop)
scoop install trivy

# Go install
go install github.com/aquasecurity/trivy/cmd/trivy@latest
```

## Core Workflow

### 1. Quick Scan

```bash
# Scan container image
trivy image nginx:latest

# Scan filesystem/project directory
trivy fs /path/to/project

# Scan current directory
trivy fs .

# Scan remote git repository
trivy repo https://github.com/owner/repo

# Scan Kubernetes cluster
trivy k8s --report summary cluster
```

### 2. SARIF Output

```bash
# Container image to SARIF
trivy image --format sarif --output results.sarif nginx:latest

# Filesystem to SARIF
trivy fs --format sarif --output results.sarif /path/to/project

# Repository to SARIF
trivy repo --format sarif --output results.sarif https://github.com/owner/repo

# IaC scan to SARIF
trivy config --format sarif --output iac-results.sarif /path/to/terraform
```

### 3. Specific Scanner Types

```bash
# Vulnerability scanning only
trivy image --scanners vuln nginx:latest

# Secrets scanning only
trivy fs --scanners secret /path/to/project

# Misconfiguration scanning only
trivy config /path/to/iac

# License scanning
trivy image --scanners license nginx:latest

# Combined scanners
trivy fs --scanners vuln,secret,misconfig /path/to/project
```

### 4. SBOM Generation

```bash
# Generate CycloneDX SBOM
trivy image --format cyclonedx --output sbom.json nginx:latest

# Generate SPDX SBOM
trivy image --format spdx-json --output sbom.spdx.json nginx:latest

# Scan existing SBOM for vulnerabilities
trivy sbom sbom.json
```

## Scan Targets

| Target | Command | Description |
|--------|---------|-------------|
| **Container Image** | `trivy image IMAGE` | Scan container images from registries or local |
| **Filesystem** | `trivy fs PATH` | Scan local project directory |
| **Repository** | `trivy repo URL` | Scan remote git repository |
| **Kubernetes** | `trivy k8s` | Scan Kubernetes cluster resources |
| **IaC/Config** | `trivy config PATH` | Scan IaC files (Terraform, CloudFormation, etc.) |
| **SBOM** | `trivy sbom FILE` | Scan existing SBOM file |
| **VM Image** | `trivy vm IMAGE` | Scan virtual machine images |
| **Rootfs** | `trivy rootfs PATH` | Scan root filesystem |

## Supported Ecosystems

### Package Managers

| Ecosystem | Manifest/Lock Files |
|-----------|---------------------|
| **npm** | package.json, package-lock.json, yarn.lock, pnpm-lock.yaml |
| **Python** | requirements.txt, Pipfile.lock, poetry.lock, setup.py |
| **Go** | go.mod, go.sum |
| **Rust** | Cargo.lock |
| **Java** | pom.xml, build.gradle, gradle.lockfile |
| **Ruby** | Gemfile.lock |
| **PHP** | composer.lock |
| **.NET** | packages.lock.json, *.deps.json |
| **Swift** | Package.resolved |
| **Dart** | pubspec.lock |
| **Elixir** | mix.lock |
| **Conan (C/C++)** | conan.lock |

### IaC Platforms

| Platform | File Types |
|----------|------------|
| **Terraform** | *.tf, *.tf.json |
| **CloudFormation** | *.yaml, *.json (CFN templates) |
| **Kubernetes** | *.yaml (K8s manifests) |
| **Helm** | Chart.yaml, values.yaml |
| **Docker** | Dockerfile |
| **Azure ARM** | *.json (ARM templates) |

## Output Formats

```bash
# Table format (default, human-readable)
trivy image nginx:latest

# JSON output
trivy image --format json --output results.json nginx:latest

# SARIF output (for CI/CD integration)
trivy image --format sarif --output results.sarif nginx:latest

# CycloneDX SBOM
trivy image --format cyclonedx --output sbom.cdx.json nginx:latest

# SPDX SBOM
trivy image --format spdx-json --output sbom.spdx.json nginx:latest

# GitHub dependency snapshot
trivy image --format github nginx:latest

# Template output (custom)
trivy image --format template --template "@contrib/html.tpl" --output report.html nginx:latest
```

## Advanced Options

### Severity Filtering

```bash
# Critical and High only
trivy image --severity CRITICAL,HIGH nginx:latest

# All severities (default)
trivy image --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL nginx:latest

# Exit with error on findings
trivy image --exit-code 1 --severity HIGH,CRITICAL nginx:latest
```

### Vulnerability Options

```bash
# Show only fixed vulnerabilities
trivy image --ignore-unfixed nginx:latest

# Ignore specific vulnerabilities
trivy image --ignorefile .trivyignore nginx:latest

# Skip vulnerability database update
trivy image --skip-db-update nginx:latest

# Offline mode (use cached DB)
trivy image --offline-scan nginx:latest
```

### Image Scanning Options

```bash
# Scan from tar archive
trivy image --input image.tar

# Scan specific platform
trivy image --platform linux/amd64 nginx:latest

# Scan with image config
trivy image --image-config-scanners config nginx:latest

# Skip files by pattern
trivy image --skip-files "/path/to/skip" nginx:latest

# Skip directories
trivy image --skip-dirs node_modules nginx:latest
```

### Secret Scanning

```bash
# Enable secret scanning
trivy fs --scanners secret /path/to/project

# Custom secret config
trivy fs --scanners secret --secret-config trivy-secret.yaml /path/to/project
```

## CI/CD Integration (GitHub Actions)

```yaml
name: Trivy Security Scan

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 0 * * *'  # Daily

jobs:
  trivy-scan:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Run Trivy vulnerability scanner (filesystem)
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          format: 'sarif'
          output: 'trivy-fs-results.sarif'
          severity: 'CRITICAL,HIGH'

      - name: Upload Trivy SARIF (filesystem)
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: 'trivy-fs-results.sarif'
          category: trivy-fs

      - name: Run Trivy config scanner (IaC)
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'config'
          scan-ref: '.'
          format: 'sarif'
          output: 'trivy-config-results.sarif'

      - name: Upload Trivy SARIF (config)
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: 'trivy-config-results.sarif'
          category: trivy-config

  container-scan:
    runs-on: ubuntu-latest
    needs: [build]  # Assuming a build job creates the image

    steps:
      - name: Run Trivy container scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'myapp:${{ github.sha }}'
          format: 'sarif'
          output: 'trivy-image-results.sarif'
          severity: 'CRITICAL,HIGH'
          ignore-unfixed: true

      - name: Upload Trivy SARIF (image)
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: 'trivy-image-results.sarif'
          category: trivy-image
```

## Configuration

### Config File (trivy.yaml)

```yaml
# trivy.yaml
severity:
  - CRITICAL
  - HIGH
  - MEDIUM

exit-code: 1

ignore-unfixed: true

# Vulnerability settings
vulnerability:
  type:
    - os
    - library

# Secret scanning
secret:
  config: trivy-secret.yaml

# Misconfiguration settings
misconfiguration:
  terraform:
    excluded-checks:
      - AVD-AWS-0013

# Skip patterns
skip-files:
  - "**/*.test.js"
  - "**/testdata/**"

skip-dirs:
  - node_modules
  - .git
  - vendor

# Cache settings
cache:
  dir: /tmp/trivy-cache
```

### Ignore File (.trivyignore)

```text
# .trivyignore
# Ignore specific CVEs
CVE-2023-12345
CVE-2023-67890

# Ignore with expiration
CVE-2024-11111 exp:2025-06-01

# Ignore specific package vulnerabilities
CVE-2024-22222 pkg:lodash

# Secret ignore patterns
aws-access-key-id
```

### Secret Config (trivy-secret.yaml)

```yaml
# trivy-secret.yaml
rules:
  - id: custom-api-key
    category: general
    title: Custom API Key
    severity: HIGH
    regex: 'CUSTOM_API_KEY[=:]\s*["\']?([A-Za-z0-9]{32})["\']?'

allow-rules:
  - id: allow-test-secrets
    description: Allow test/mock secrets
    path: '.*test.*|.*mock.*'
```

## Common Use Cases

### 1. Container Security Pipeline

```bash
# Build image
docker build -t myapp:latest .

# Scan for vulnerabilities
trivy image --severity HIGH,CRITICAL --exit-code 1 myapp:latest

# Generate SBOM
trivy image --format cyclonedx --output sbom.json myapp:latest

# Export SARIF for tracking
trivy image --format sarif --output results.sarif myapp:latest
```

### 2. IaC Security Review

```bash
# Scan Terraform files
trivy config --format sarif --output iac-results.sarif ./terraform

# Scan Kubernetes manifests
trivy config --format sarif --output k8s-results.sarif ./k8s

# Scan Dockerfiles
trivy config --format sarif --output docker-results.sarif .
```

### 3. Repository Security Audit

```bash
# Full repository scan
trivy fs --scanners vuln,secret,misconfig \
  --format sarif --output full-scan.sarif \
  /path/to/project

# Scan remote repository
trivy repo --format sarif --output repo-scan.sarif \
  https://github.com/owner/repo
```

### 4. Kubernetes Cluster Assessment

```bash
# Summary report
trivy k8s --report summary cluster

# Detailed scan with SARIF
trivy k8s --format sarif --output k8s-cluster.sarif cluster

# Scan specific namespace
trivy k8s --namespace production --report all cluster
```

### 5. Supply Chain Security

```bash
# Generate SBOM
trivy image --format cyclonedx --output sbom.cdx.json myapp:latest

# Scan SBOM for vulnerabilities
trivy sbom sbom.cdx.json

# Sign SBOM with cosign (if available)
cosign sign-blob --key cosign.key sbom.cdx.json
```

## Understanding Output

### SARIF Structure

Trivy SARIF v2.1.0 includes:

- **Rules**: Each vulnerability, misconfiguration, or secret type
- **Results**: Individual findings with location
- **Properties**:
  - CVE/vulnerability ID
  - Severity (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN)
  - CVSS scores
  - Package name and version
  - Fixed version (if available)
  - References and links
  - File path and line number (for secrets/misconfig)

### Vulnerability Information

Each finding includes:

- **VulnerabilityID**: CVE-YYYY-NNNNN
- **PkgName**: Affected package name
- **InstalledVersion**: Current vulnerable version
- **FixedVersion**: Version with fix (if available)
- **Severity**: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
- **Title**: Brief vulnerability description
- **Description**: Detailed explanation
- **References**: Links to advisories
- **CVSS**: Score vectors if available

## Remediation Workflow

### Step 1: Scan

```bash
trivy image --format json --output vulns.json myapp:latest
```

### Step 2: Prioritize

```bash
# Extract critical vulnerabilities
jq '.Results[].Vulnerabilities[] | select(.Severity == "CRITICAL")' vulns.json

# Count by severity
jq '[.Results[].Vulnerabilities[].Severity] | group_by(.) | map({severity: .[0], count: length})' vulns.json
```

### Step 3: Fix

```bash
# Review fix versions
jq -r '.Results[].Vulnerabilities[] | select(.FixedVersion != null) | "\(.PkgName): \(.InstalledVersion) -> \(.FixedVersion)"' vulns.json

# Update base image
# Edit Dockerfile: FROM nginx:1.25-alpine (newer patched version)

# Rebuild
docker build -t myapp:latest .
```

### Step 4: Verify

```bash
# Rescan
trivy image --format json --output post-fix.json myapp:latest

# Compare vulnerability counts
echo "Before: $(jq '[.Results[].Vulnerabilities[]] | length' vulns.json)"
echo "After: $(jq '[.Results[].Vulnerabilities[]] | length' post-fix.json)"
```

## Performance Optimization

```bash
# Skip database update (use cached)
trivy image --skip-db-update nginx:latest

# Offline scanning
trivy image --offline-scan nginx:latest

# Skip specific directories
trivy fs --skip-dirs node_modules,.git,vendor /path/to/project

# Cache directory (faster subsequent scans)
trivy image --cache-dir /tmp/trivy-cache nginx:latest

# Parallel scanning (default)
trivy image --parallel 4 nginx:latest
```

## Database Management

```bash
# Download/update vulnerability database
trivy image --download-db-only

# Clear cache
trivy clean --all

# Check database status
trivy version --format json | jq '.VulnerabilityDB'
```

## Limitations

- **Image layers**: Only scans final image filesystem, not intermediate layers
- **Runtime**: Static analysis only; doesn't detect runtime vulnerabilities
- **Custom packages**: May not detect vulnerabilities in custom/private packages
- **False positives**: OS package detection may include packages not actually installed
- **Zero-days**: Only detects publicly disclosed vulnerabilities

## Rationalizations to Reject

| Shortcut | Why It's Wrong |
|----------|----------------|
| "Base image from vendor is secure" | Vendors lag on patches; always scan regardless of source |
| "Only scan production images" | Dev/staging images can leak secrets or introduce supply chain attacks |
| "Skip IaC scanning for speed" | Misconfigurations are easier to fix before deployment |
| "Ignore unfixed vulnerabilities" | Even without patches, you can mitigate or compensate with other controls |
| "Weekly scans are enough" | New CVEs are disclosed daily; scan on every build and daily on deployed images |
| "Low severity = safe to ignore" | Low severity issues can combine into exploitable chains |

## References

- Repository: <https://github.com/aquasecurity/trivy>
- Documentation: <https://trivy.dev/>
- GitHub Action: <https://github.com/aquasecurity/trivy-action>
- Trivy Operator (Kubernetes): <https://github.com/aquasecurity/trivy-operator>
- VS Code Extension: <https://marketplace.visualstudio.com/items?itemName=AquaSecurityOfficial.trivy-vulnerability-scanner>
- Vulnerability Database: <https://github.com/aquasecurity/trivy-db>
- SARIF Spec: <https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html>
