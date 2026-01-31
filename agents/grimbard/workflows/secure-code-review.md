---
description: Workflow for conducting a comprehensive secure code review of an unknown codebase
---

# Secure Code Review Workflow

This workflow provides a structured approach for security code reviewers to analyze an unknown codebase using a combination of automated tools and manual deep-dive analysis.

---

## Phase 1: Initial Discovery & Reconnaissance

**Goal:** Develop a foundational understanding of the codebase before diving into security analysis.

### 1.1 Repository Structure Analysis

- [ ] Clone/access the repository and review the directory structure
- [ ] Identify the technology stack (languages, frameworks, libraries)
- [ ] Review `README.md`, documentation folders, and architecture diagrams
- [ ] Identify build systems, package managers, and dependency files
  - `package.json`, `requirements.txt`, `pom.xml`, `go.mod`, `Gemfile`, etc.
- [ ] Map out entry points (main files, API routes, CLI handlers)
- [ ] **Tool:** Run `noir` to identify the attack surface (API endpoints, routes).

  ```bash
  // turbo
  noir -b . -T --format sarif -o noir-results.sarif
  ```

### 1.2 Dependency Inventory

- [ ] Generate a Software Bill of Materials (SBOM)
- [ ] Identify third-party libraries and their versions
- [ ] Note any vendored or forked dependencies
- [ ] Check for dependency lock files and their freshness

### 1.3 Configuration Analysis

- [ ] Identify configuration files (`.env`, `config.yaml`, etc.)
- [ ] Review deployment configurations (Docker, K8s, Terraform)
- [ ] Check for hardcoded secrets or credentials
- [ ] Identify authentication/authorization configuration
- [ ] **Tool:** Run `kics` to scan IaC and configuration files (Docker, K8s, Terraform).

  ```bash
  // turbo
  docker run -v ${PWD}:/path checkmarx/kics scan -p /path -o /path --output-name kics-results --report-formats sarif
  ```

### 1.4 Data Flow Mapping

- [ ] Identify data entry points (APIs, file uploads, user inputs)
- [ ] Map data storage locations (databases, caches, file systems)
- [ ] Trace data flow from input to storage to output
- [ ] Document trust boundaries

### 📝 Phase 1 Documentation

- [ ] Create architecture diagram based on understanding
- [ ] Document technology stack summary
- [ ] **Tool:** Run `appinspector` to analyze features and technology usage.

  ```bash
  // turbo
  appinspector analyze -s . -o appinspector-results.html -f html
  ```

- [ ] Record initial security hypotheses and areas of concern
- [ ] Note questions for development team

---

## Phase 2: Automated Static Analysis

**Goal:** Leverage automated tools to identify potential security issues quickly.

### 2.1 Secret Scanning

```bash
# Run secret detection tools
// turbo
gitleaks detect --source . --verbose
trufflehog filesystem . --only-verified
```

- [ ] Scan for hardcoded secrets, API keys, and credentials
- [ ] Check git history for previously committed secrets
- [ ] Review results and triage findings

### 2.2 Dependency Vulnerability Scanning

```bash
# Run dependency vulnerability scanners
# Google OSV Scanner
osv-scanner -r . --format sarif --output osv-results.sarif
# OWASP Depscan
docker run --rm -v ${PWD}:/app ghcr.io/owasp-dep-scan/dep-scan --src /app --reports-dir /app/reports
```

- [ ] Identify known vulnerabilities in dependencies (CVEs)
- [ ] Assess severity and exploitability of each finding
- [ ] Check for available patches or updates

### 2.3 Static Application Security Testing (SAST)

```bash
# Run SAST tools
// turbo
# Opengrep (Semgrep fork)
opengrep scan --config auto . --sarif --output opengrep-results.sarif

# CodeQL
codeql database create codeql-db --language=<lang>
codeql database analyze codeql-db --format=sarif-latest --output=results.sarif

- [ ] Run language-specific security analyzers
- [ ] Use Opengrep (preferred) or Semgrep with security-focused rulesets
- [ ] Use CodeQL if the code is open-source (check LICENSE.md)
- [ ] Collect SARIF outputs for consolidated analysis

### 2.4 Code Quality & Complexity Analysis

```bash
# Measure code complexity
// turbo
lizard . --CCN 15  # Cyclomatic complexity
radon cc . -a  # Python complexity
# Measure code complexity
// turbo
lizard . --CCN 15  # Cyclomatic complexity
radon cc . -a  # Python complexity
cloc .             # Lines of Code and Language breakdown
```

- [ ] Identify highly complex functions (candidates for bugs)
- [ ] Note code hotspots with high change frequency
- [ ] Flag functions lacking test coverage

### 📝 Phase 2 Documentation

- [ ] Save all tool output files (SARIF, JSON, logs)
- [ ] Create summary table of findings by severity
- [ ] Document tool versions and configurations used
- [ ] Note any tools that failed or had limited results

---

## Phase 3: SARIF Triage & Prioritization

**Goal:** Consolidate and prioritize findings from automated tools.

### 3.1 SARIF Aggregation

- [ ] Consolidate all SARIF files into a central location
- [ ] Use SARIF viewers (VS Code extension, web viewers) for analysis
- [ ] Map findings to files and line numbers

### 3.2 Finding Classification

- [ ] Categorize findings by vulnerability type (OWASP Top 10, CWE)
- [ ] Classify by severity: Critical, High, Medium, Low, Informational
- [ ] Identify false positives based on context

### 3.3 Prioritization Matrix

| Priority | Criteria |
| :--- | :--- |
| P0 (Critical) | Exploitable RCE, SQLi, Auth bypass in production |
| P1 (High) | XSS, SSRF, IDOR, sensitive data exposure |
| P2 (Medium) | CSRF, information disclosure, weak crypto |
| P3 (Low) | Missing security headers, verbose errors |

### 📝 Phase 3 Documentation

- [ ] Create prioritized backlog of findings for manual review
- [ ] Document false positive rationale for each dismissal
- [ ] Group related findings and identify patterns
- [ ] Export triaged finding list with initial verdicts

---

## Phase 4: Deep Manual Review

**Goal:** Manually analyze high-risk areas that automated tools cannot fully assess.

### 4.1 Authentication & Session Management

- [ ] Review authentication mechanisms (password handling, MFA)
- [ ] Analyze session token generation and validation
- [ ] Check for session fixation, hijacking vulnerabilities
- [ ] Review password reset flows
- [ ] Verify OAuth/OIDC implementation if present

### 4.2 Authorization & Access Control

- [ ] Trace authorization checks from entry points
- [ ] Verify principle of least privilege
- [ ] Check for IDOR (Insecure Direct Object References)
- [ ] Review role-based access control implementation
- [ ] Test for privilege escalation paths

### 4.3 Input Validation & Output Encoding

- [ ] Identify all user input sources
- [ ] Verify server-side validation (don't trust client-side only)
- [ ] Check for injection vulnerabilities (SQL, NoSQL, Command, LDAP)
- [ ] Review output encoding for XSS prevention
- [ ] Analyze file upload handling

### 4.4 Cryptography Review

- [ ] Review encryption algorithms and modes
- [ ] Check key management practices
- [ ] Verify proper random number generation
- [ ] Assess hashing algorithms (especially for passwords)
- [ ] Check TLS configuration

### 4.5 Error Handling & Logging

- [ ] Verify sensitive data is not logged
- [ ] Check error messages for information disclosure
- [ ] Review exception handling completeness
- [ ] Assess audit logging coverage

### 4.6 Business Logic Review

- [ ] Understand critical business workflows
- [ ] Check for race conditions in concurrent operations
- [ ] Review financial/transactional logic for bypasses
- [ ] Identify state machine flaws

### 📝 Phase 4 Documentation

For each finding discovered, document immediately:

```markdown
## [FINDING-ID]: [Title]
**Severity:** Critical/High/Medium/Low (CVSS 3.1 base vector string)
**CWE:** CWE-XXX
**Location:** `path/to/file.py:123`

### Description
[Clear explanation of the vulnerability]

### Impact
[What harm can an attacker cause]

### Proof of Concept
[Steps to reproduce or code demonstrating the issue]

### Remediation
[Specific recommendations for fixing]
```

- [ ] Mark reviewed code sections in notes
- [ ] Record areas requiring further investigation
- [ ] Note positive security observations

---

## Phase 5: Iterative Deepening

**Goal:** Drill down into specific areas based on initial findings.

### 5.1 Pattern-Based Analysis

- [ ] Use findings from Phase 4 to identify anti-patterns
- [ ] Search codebase for similar vulnerability patterns
- [ ] Create custom Semgrep rules for project-specific issues

```bash
# Search for patterns across codebase
grep -rn "eval(" --include="*.py" .
grep -rn "innerHTML" --include="*.js" .
grep -rn "dangerouslySetInnerHTML" --include="*.jsx" .
```

### 5.2 Variant Analysis

- [ ] For each confirmed vulnerability, search for variants
- [ ] Use CodeQL variant analysis if available
- [ ] Check similar code paths for same vulnerability type

### 5.3 Data Flow Tracing

- [ ] For high-risk findings, trace complete data flow
- [ ] Identify sanitization gaps
- [ ] Map trust boundary crossings

### 5.4 Threat Modeling

- [ ] Create/update threat model based on review findings
- [ ] Identify STRIDE threats for critical components
- [ ] Document attack trees for high-risk scenarios

### 📝 Phase 5 Documentation

- [ ] Add variant findings to main findings list
- [ ] Document custom detection rules created
- [ ] Update threat model documentation
- [ ] Record attack paths discovered

---

## Phase 6: Reporting

**Goal:** Produce actionable reports for stakeholders.

### 6.1 Executive Summary

- [ ] High-level overview of security posture
- [ ] Key statistics (findings by severity)
- [ ] Top 3-5 risks requiring immediate attention
- [ ] Overall risk rating

### 6.2 Technical Report Structure

```markdown
1. Executive Summary
2. Scope and Methodology
3. Summary of Findings
4. Detailed Findings (by severity)
5. Positive Security Observations
6. Recommendations (prioritized)
7. Appendix: Tools Used, SARIF Files, etc.
```

### 6.3 Remediation Guidance

- [ ] Provide specific, actionable remediation steps
- [ ] Prioritize based on risk and effort
- [ ] Include code examples for fixes where helpful
- [ ] Reference secure coding guidelines

### 6.4 Metrics & Tracking

- [ ] Link issues to specific code locations
- [ ] Assign severity and due dates
- [ ] Track remediation progress

---

## Appendix: Recommended Tools

| Category | Tools |
|----------|-------|
| Secret Scanning | [Gitleaks](https://github.com/gitleaks/gitleaks), [TruffleHog](https://github.com/trufflesecurity/trufflehog) |
| Dependency Scanning | [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/) |
| SAST | [Semgrep](https://semgrep.dev/), [CodeQL](https://codeql.github.com/), [Bandit](https://bandit.readthedocs.io/) (Python), [Gosec](https://securego.io/) (Go) |
| Complexity | [Lizard](https://github.com/terryyin/lizard), [Radon](https://radon.readthedocs.io/) (Python) |
| SARIF Viewers | [VS Code SARIF Viewer](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer) |

### Additional Tools from Baldwin.sh

| Tool | Purpose | Command / Link |
| :--- | :--- | :--- |
| **[Opengrep](https://github.com/opengrep/opengrep)** | Static Analysis (Semgrep fork) | `opengrep scan ...` |
| **[OWASP Noir](https://github.com/owasp-noir/noir)** | Attack Surface Detector | `noir -b . ...` |
| **[KICS](https://github.com/Checkmarx/kics)** | IaC Security Scanner | `checkmarx/kics` (Docker) |
| **[AppInspector](https://github.com/microsoft/ApplicationInspector)** | Feature/Tech Analysis | `appinspector analyze ...` |
| **[OSV-Scanner](https://github.com/google/osv-scanner)** | Vulnerability Scanner | `osv-scanner ...` |
| **[OWASP dep-scan](https://github.com/owasp-dep-scan/dep-scan)** | SCA / Dependency check | `ghcr.io/owasp-dep-scan/dep-scan` |
| **[cloc](https://github.com/AlDanial/cloc)** | Lines of Code Counter | `cloc .` |

---

## Checklist Summary

| Phase | Status |
|-------|--------|
| Phase 1: Initial Discovery | [ ] |
| Phase 2: Automated Static Analysis | [ ] |
| Phase 3: SARIF Triage | [ ] |
| Phase 4: Deep Manual Review | [ ] |
| Phase 5: Iterative Deepening | [ ] |
| Phase 6: Reporting | [ ] |
