# Compliance Audit Workflow

**Duration**: 6-10 hours
**Purpose**: Validate code security against compliance frameworks (PCI-DSS, HIPAA, SOC 2, GDPR)
**Output**: Compliance-focused security assessment with framework control mappings

---

## Overview

The Compliance Audit workflow performs a comprehensive security review specifically focused on regulatory and compliance requirements. This workflow:

- Maps security findings to compliance framework controls
- Validates framework-specific security requirements
- Generates audit-ready documentation
- Identifies compliance gaps
- Provides remediation guidance aligned with compliance standards

**Supported Frameworks**:
- **PCI-DSS v4.0** - Payment Card Industry Data Security Standard
- **HIPAA** - Health Insurance Portability and Accountability Act
- **SOC 2 Type II** - System and Organization Controls
- **GDPR** - General Data Protection Regulation

---

## Prerequisites

### Required Knowledge

- Understanding of target compliance framework
- Application's data handling and storage practices
- Existing compliance documentation

### Required Tools

Same as complete security review:
- Opengrep/Semgrep, Gitleaks, KICS, Noir, OSV-Scanner, Depscan, Application Inspector

### Preparation

```bash
# Identify compliance scope
export COMPLIANCE_FRAMEWORK=PCI-DSS  # or HIPAA, SOC2, GDPR

# Identify sensitive data types
export DATA_CLASSIFICATION="cardholder-data"  # or PHI, PII, personal-data

# Set compliance requirements directory
export COMPLIANCE_DOCS=./compliance-docs
```

---

## Phase 1: Compliance Scoping (1 hour)

### Objective

Identify which parts of the codebase are in scope for compliance and what controls apply.

### Steps

#### 1.1 Data Flow Mapping

```bash
# Identify data entry points
noir -b /path/to/project --format sarif -o ./compliance-audit/attack-surface.sarif

# Review API endpoints that handle sensitive data
noir -b /path/to/project --format markdown-table | grep -E "POST|PUT|PATCH"

# Identify data storage locations
grep -r "database" --include="*.{js,py,go,java}" /path/to/project
grep -r "storage" --include="*.{js,py,go,java}" /path/to/project
```

#### 1.2 Framework Control Mapping

**PCI-DSS v4.0 Key Requirements**:
- Requirement 3: Protect stored cardholder data
- Requirement 4: Encrypt transmission of cardholder data
- Requirement 6: Develop and maintain secure systems
- Requirement 8: Identify and authenticate access
- Requirement 10: Log and monitor all access

**HIPAA Security Rule**:
- Access Control (164.312(a))
- Audit Controls (164.312(b))
- Integrity (164.312(c))
- Transmission Security (164.312(e))

**SOC 2 Trust Service Criteria**:
- CC6.1: Logical and physical access controls
- CC6.6: Protection of confidential information
- CC7.2: System monitoring
- CC8.1: Vulnerability management

**GDPR Requirements**:
- Article 25: Data protection by design
- Article 32: Security of processing
- Article 33: Breach notification
- Article 35: Data protection impact assessment

#### 1.3 Create Compliance Matrix Template

```bash
cat > ./compliance-audit/compliance-matrix.md << 'EOF'
# Compliance Control Matrix

**Framework**: [PCI-DSS/HIPAA/SOC2/GDPR]
**Application**: [name]
**Audit Date**: [date]
**Auditor**: [name]

## Control Coverage

| Control ID | Control Description | Code Evidence | Finding | Status | Notes |
|------------|---------------------|---------------|---------|--------|-------|
| [ID] | [Description] | [file:line] | [SARIF finding] | ✓/✗/⚠ | [details] |

EOF
```

---

## Phase 2: Automated Compliance Scanning (2-3 hours)

### Objective

Run security tools with compliance-specific rule sets and configurations.

### Framework-Specific Tool Configurations

#### 2.1 PCI-DSS Configuration

```bash
# Opengrep with PCI-DSS rules
opengrep scan \
  --config "p/pci-dss" \
  --sarif \
  --output ./compliance-audit/sarif/opengrep-pci.sarif \
  /path/to/project

# Gitleaks (critical for Requirement 3 - no stored cardholder data)
gitleaks detect \
  --source=/path/to/project \
  --report-format=sarif \
  --report-path=./compliance-audit/sarif/gitleaks.sarif \
  --no-banner \
  --redact

# KICS for infrastructure compliance
kics scan \
  -p /path/to/project \
  --report-formats sarif \
  --output-path ./compliance-audit/sarif/kics-pci.sarif
```

**PCI-DSS Specific Checks**:
- Strong cryptography (Req 3, 4)
- No hardcoded cardholder data (Req 3)
- Secure authentication (Req 8)
- Access logging (Req 10)
- Vulnerability management (Req 6)

#### 2.2 HIPAA Configuration

```bash
# Opengrep with HIPAA/healthcare rules
opengrep scan \
  --config "p/hipaa" \
  --config "p/owasp-top-ten" \
  --sarif \
  --output ./compliance-audit/sarif/opengrep-hipaa.sarif \
  /path/to/project

# Focus on PHI handling
grep -r "patient\|medical\|diagnosis\|prescription" --include="*.{js,py,go}" /path/to/project
```

**HIPAA Specific Checks**:
- Encryption of ePHI (164.312(a)(2)(iv))
- Access controls (164.312(a)(1))
- Audit controls (164.312(b))
- Transmission security (164.312(e)(1))

#### 2.3 SOC 2 Configuration

```bash
# Opengrep with security best practices
opengrep scan \
  --config "p/security-audit" \
  --config "p/secrets" \
  --sarif \
  --output ./compliance-audit/sarif/opengrep-soc2.sarif \
  /path/to/project

# Application Inspector for security features inventory
appinspector analyze \
  -s /path/to/project \
  --output-file-format sarif \
  --output-file-path ./compliance-audit/sarif/app-inspector-soc2.sarif
```

**SOC 2 Specific Checks**:
- Logical access controls (CC6.1)
- Encryption of sensitive data (CC6.6)
- System monitoring capabilities (CC7.2)
- Vulnerability management (CC8.1)

#### 2.4 GDPR Configuration

```bash
# Opengrep with privacy-focused rules
opengrep scan \
  --config "p/privacy" \
  --config "p/gdpr" \
  --sarif \
  --output ./compliance-audit/sarif/opengrep-gdpr.sarif \
  /path/to/project

# Identify personal data processing
grep -r "email\|phone\|address\|ssn\|passport" --include="*.{js,py,go}" /path/to/project
```

**GDPR Specific Checks**:
- Data minimization (Art 5.1c)
- Security of processing (Art 32)
- Data protection by design (Art 25)
- Breach detection (Art 33)

---

## Phase 3: Compliance Control Validation (2-3 hours)

### Objective

Manually validate each framework control against code evidence.

### 3.1 PCI-DSS Control Validation

#### Requirement 3: Protect Stored Cardholder Data

**Control 3.3.1**: Verify no stored sensitive authentication data (SAD)

```bash
# Search for prohibited data elements
grep -ri "cvv\|cvc\|card.*verification" --include="*.{js,py,go,java,sql}" /path/to/project
grep -ri "full.*track.*data\|magnetic.*stripe" --include="*.{js,py,go,java,sql}" /path/to/project
grep -ri "pin\|personal.*identification.*number" --include="*.{js,py,go,java,sql}" /path/to/project

# Check database schemas for SAD storage
find /path/to/project -name "*.sql" -exec grep -l "cvv\|cvc\|pin" {} \;
```

**Control 3.4.1**: Verify PAN is rendered unreadable

```bash
# Check for encryption of cardholder data
opengrep -e "card.*number.*=" -lang js,py,go /path/to/project
opengrep -e "pan.*=" -lang js,py,go /path/to/project

# Verify encryption functions used
grep -r "encrypt\|hash\|tokenize" --include="*.{js,py,go}" /path/to/project | grep -i card
```

#### Requirement 4: Encrypt Transmission

**Control 4.2.1**: Verify strong cryptography for transmission

```bash
# Check TLS/SSL configuration
grep -r "TLSv1.2\|TLSv1.3" /path/to/project
grep -r "ssl.*version\|tls.*version" /path/to/project

# Verify no weak protocols
grep -ri "SSLv2\|SSLv3\|TLSv1.0\|TLSv1.1" /path/to/project && echo "FAIL: Weak protocols found"
```

#### Requirement 6: Secure Development

**Control 6.2.4**: Verify vulnerability management

```bash
# Run dependency scanning
osv-scanner scan --format sarif /path/to/project > ./compliance-audit/sarif/osv-scanner.sarif
depscan --src /path/to/project --reports-dir ./compliance-audit --report-template sarif

# Check for known vulnerable dependencies
python -m sarif_tools summary ./compliance-audit/sarif/osv-scanner.sarif
```

#### Requirement 8: Authentication

**Control 8.3.1**: Verify multi-factor authentication

```bash
# Search for MFA implementation
grep -r "mfa\|multi.*factor\|two.*factor\|2fa" --include="*.{js,py,go}" /path/to/project

# Check authentication middleware
find /path/to/project -name "*auth*.{js,py,go}" -exec cat {} \; | grep -i "factor\|otp\|totp"
```

#### Requirement 10: Logging

**Control 10.2.1**: Verify audit logging

```bash
# Check for logging of security events
grep -r "logger\|log\.\|console.log" --include="*.{js,py,go}" /path/to/project | grep -i "auth\|login\|access"

# Verify log content includes required elements
# - User ID, Event type, Date/time, Success/failure, Origination, Identity/name of resource
```

### 3.2 HIPAA Control Validation

#### 164.312(a)(1) - Access Control

```bash
# Verify unique user identification
grep -r "user.*id\|username" --include="*.{js,py,go}" /path/to/project

# Check for role-based access control
grep -r "role\|permission\|authorize" --include="*.{js,py,go}" /path/to/project
```

#### 164.312(b) - Audit Controls

```bash
# Verify audit logging for ePHI access
grep -r "audit\|log.*access\|activity.*log" --include="*.{js,py,go}" /path/to/project

# Check logs include ePHI access events
```

#### 164.312(e)(1) - Transmission Security

```bash
# Verify encryption in transit
grep -r "https\|tls\|ssl" /path/to/project
grep -r "encrypt.*transmit\|secure.*transmission" /path/to/project

# Verify no plaintext PHI transmission
grep -ri "http://" /path/to/project | grep -v "localhost\|127.0.0.1" && echo "WARNING: HTTP found"
```

### 3.3 SOC 2 Control Validation

#### CC6.1 - Logical Access Controls

```bash
# Verify authentication mechanisms
grep -r "authenticate\|login\|signin" --include="*.{js,py,go}" /path/to/project

# Check authorization before sensitive operations
opengrep -e "authorize.*before.*" -lang js,py,go /path/to/project
```

#### CC6.6 - Encryption of Confidential Information

```bash
# Verify encryption at rest
grep -r "encrypt\|cipher\|crypto" --include="*.{js,py,go}" /path/to/project

# Check key management
grep -r "key.*management\|kms\|vault" /path/to/project
```

#### CC7.2 - System Monitoring

```bash
# Verify monitoring and alerting
grep -r "monitor\|alert\|metric" --include="*.{js,py,go}" /path/to/project

# Check for security event monitoring
grep -r "security.*event\|intrusion\|anomaly" /path/to/project
```

### 3.4 GDPR Control Validation

#### Article 25 - Data Protection by Design

```bash
# Verify data minimization
grep -r "collect.*data\|gather.*information" --include="*.{js,py,go}" /path/to/project

# Check for privacy-by-default settings
grep -r "privacy\|consent\|opt.*in" /path/to/project
```

#### Article 32 - Security of Processing

```bash
# Verify pseudonymization/encryption
grep -r "pseudonym\|anonymize\|encrypt" --include="*.{js,py,go}" /path/to/project

# Check for security measures
opengrep -e "security.*measure\|protect.*data" -lang js,py,go /path/to/project
```

#### Article 33 - Breach Notification

```bash
# Verify breach detection capabilities
grep -r "breach.*detect\|security.*incident\|data.*leak" --include="*.{js,py,go}" /path/to/project

# Check for incident response procedures
find /path/to/project -name "*incident*" -o -name "*breach*"
```

---

## Phase 4: Gap Analysis (1-2 hours)

### Objective

Identify controls that are not met and document remediation requirements.

### 4.1 Create Gap Analysis Report

```bash
cat > ./compliance-audit/gap-analysis.md << 'EOF'
# Compliance Gap Analysis

**Framework**: [PCI-DSS/HIPAA/SOC2/GDPR]
**Date**: [date]

## Executive Summary

**Total Controls Reviewed**: [count]
**Controls Met**: [count] ([percentage]%)
**Controls Partially Met**: [count]
**Controls Not Met**: [count]
**Critical Gaps**: [count]

---

## Critical Gaps (Immediate Remediation Required)

### Gap 1: [Control ID] - [Control Name]

**Requirement**: [What the framework requires]
**Current State**: [What the code does now]
**Evidence**: [SARIF findings, file locations]
**Risk Level**: Critical/High/Medium/Low
**Remediation**:
1. [Specific action 1]
2. [Specific action 2]
**Timeline**: [Immediate/1 week/1 month]
**Owner**: [Team/individual responsible]

---

## Partial Compliance (Improvement Needed)

### Gap 2: [Control ID] - [Control Name]

[Same structure as above]

---

## Recommendations

1. **Immediate Actions** (0-30 days):
   - Fix critical gaps
   - Implement missing controls

2. **Short-term Actions** (1-3 months):
   - Address partial compliance
   - Enhance existing controls

3. **Long-term Actions** (3-12 months):
   - Continuous monitoring
   - Process improvements

EOF
```

### 4.2 Map Findings to Controls

```bash
# Create control mapping spreadsheet
cat > ./compliance-audit/control-mapping.csv << 'EOF'
Control ID,Control Description,SARIF Finding,File,Line,Status,Remediation
PCI-3.3.1,No stored SAD,gitleaks-cvv-found,payments.py,45,FAIL,Remove CVV storage
PCI-4.2.1,Strong crypto for transmission,semgrep-weak-tls,config.js,12,FAIL,Upgrade to TLS 1.2+
PCI-6.2.4,Vulnerability management,osv-scanner-cve-2023-1234,package.json,8,FAIL,Update dependency
...
EOF
```

---

## Phase 5: Remediation Guidance (1 hour)

### Objective

Provide specific, actionable remediation steps for each gap.

### 5.1 Framework-Specific Remediation Templates

#### PCI-DSS Remediation

**For Requirement 3 (Data Protection)**:
```bash
# Remove prohibited data storage
1. Identify all SAD storage locations (CVV, PIN, full track data)
2. Delete SAD from databases
3. Remove SAD from application code
4. Implement tokenization for PAN
5. Verify no SAD in logs, backups, or error messages
```

**For Requirement 4 (Encryption)**:
```bash
# Implement strong encryption for transmission
1. Configure TLS 1.2 or higher
2. Use strong cipher suites (ECDHE-RSA-AES256-GCM-SHA384)
3. Disable weak protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
4. Implement certificate validation
5. Test with SSL Labs or similar
```

#### HIPAA Remediation

**For Access Control (164.312(a))**:
```bash
# Implement unique user identification
1. Remove shared accounts
2. Implement individual user credentials
3. Enforce strong password policy
4. Implement session management
5. Add role-based access control
```

**For Audit Controls (164.312(b))**:
```bash
# Implement comprehensive audit logging
1. Log all ePHI access (read, write, delete)
2. Include user ID, timestamp, action, resource
3. Protect logs from tampering (write-once storage)
4. Retain logs per retention policy
5. Implement log monitoring and alerting
```

#### SOC 2 Remediation

**For CC6.1 (Access Controls)**:
```bash
# Enhance logical access controls
1. Implement MFA for all users
2. Regular access reviews
3. Least privilege principle
4. Automated provisioning/deprovisioning
5. Session timeout enforcement
```

#### GDPR Remediation

**For Article 32 (Security)**:
```bash
# Implement appropriate security measures
1. Pseudonymization of personal data
2. Encryption at rest and in transit
3. Regular security testing
4. Incident detection and response
5. Data minimization techniques
```

---

## Phase 6: Compliance Reporting (1 hour)

### Objective

Generate audit-ready documentation for auditors and compliance teams.

### 6.1 Executive Compliance Report

```bash
cat > ./compliance-audit/COMPLIANCE_REPORT.md << 'EOF'
# Compliance Audit Report

**Framework**: [PCI-DSS v4.0 / HIPAA / SOC 2 Type II / GDPR]
**Application**: [Application Name]
**Version**: [Version]
**Audit Date**: [Date]
**Auditor**: [Name]
**Scope**: [Components in scope]

---

## Executive Summary

This report documents the compliance audit of [Application] against [Framework] requirements.

**Overall Compliance Score**: [X]%

**Key Findings**:
- ✓ [X] controls fully compliant
- ⚠ [X] controls partially compliant
- ✗ [X] controls non-compliant
- 🔴 [X] critical gaps requiring immediate attention

**Audit Opinion**: [Pass with recommendations / Conditional pass / Fail]

---

## Scope and Methodology

### Audit Scope

**In-Scope Components**:
- [Component 1]: [Description]
- [Component 2]: [Description]

**Out-of-Scope**:
- [Component]: [Reason]

### Methodology

1. Automated security scanning (8 tools)
2. Manual code review of security controls
3. Control mapping to framework requirements
4. Gap analysis and risk assessment
5. Remediation guidance development

### Tools Used

- Opengrep/Semgrep - SAST
- Gitleaks - Secrets detection
- KICS - IaC security
- OSV-Scanner - Dependency vulnerabilities
- Depscan - Advanced SCA
- Noir - Attack surface mapping
- Application Inspector - Security features

---

## Framework Controls Assessment

### [Framework] Requirements

| Req ID | Requirement | Status | Evidence | Notes |
|--------|-------------|--------|----------|-------|
| [ID] | [Description] | ✓/⚠/✗ | [file:line] | [comments] |

[Detailed table for all controls...]

---

## Findings Summary

### Critical Findings (Immediate Action Required)

**Finding 1**: [Title]
- **Control**: [Control ID]
- **Description**: [What was found]
- **Location**: [file:line]
- **Risk**: [Impact description]
- **Remediation**: [Specific steps]
- **Timeline**: Immediate (0-7 days)

### High Priority Findings

[Similar structure...]

### Medium Priority Findings

[Similar structure...]

---

## Compliance Gaps

### Gap 1: [Control Area]

**Current State**: [Description of current implementation]
**Required State**: [What compliance requires]
**Gap**: [Specific deficiency]
**Remediation Plan**:
1. [Action 1] - [Timeline] - [Owner]
2. [Action 2] - [Timeline] - [Owner]

---

## Remediation Roadmap

### Phase 1: Immediate (0-30 days)
- [ ] Fix critical gaps ([count] items)
- [ ] Address high-priority findings
- [ ] Implement missing mandatory controls

### Phase 2: Short-term (1-3 months)
- [ ] Address medium-priority findings
- [ ] Enhance existing controls
- [ ] Implement compensating controls

### Phase 3: Long-term (3-12 months)
- [ ] Continuous improvement
- [ ] Automated compliance monitoring
- [ ] Regular re-assessment

---

## Appendices

### Appendix A: SARIF Reports
- [List of SARIF files]

### Appendix B: Control Matrix
- [Detailed control mapping spreadsheet]

### Appendix C: Evidence
- [Code snippets, configuration files, logs]

### Appendix D: Tool Configurations
- [Tool versions, rule sets used]

---

**Report Prepared By**: [Name]
**Date**: [Date]
**Next Review Date**: [Date + 1 year or framework requirement]

EOF
```

### 6.2 Generate Framework-Specific Attestation

```bash
# PCI-DSS Attestation of Compliance (AOC) Template
# HIPAA Security Risk Assessment Documentation
# SOC 2 Readiness Report
# GDPR Data Protection Impact Assessment (DPIA)

# Each framework has specific documentation requirements
```

---

## Output Structure

```
compliance-audit/
├── sarif/
│   ├── opengrep-[framework].sarif
│   ├── gitleaks.sarif
│   ├── kics-[framework].sarif
│   ├── osv-scanner.sarif
│   ├── depscan.sarif
│   └── app-inspector.sarif
├── COMPLIANCE_REPORT.md
├── compliance-matrix.md
├── gap-analysis.md
├── control-mapping.csv
├── remediation-plan.md
├── evidence/
│   ├── screenshots/
│   ├── configs/
│   └── logs/
└── attestation/
    └── [framework]-attestation.pdf
```

---

## Success Criteria

Compliance audit is successful when:

- ✓ All framework controls reviewed and assessed
- ✓ Control status documented (pass/partial/fail)
- ✓ Code evidence mapped to each control
- ✓ Gap analysis completed
- ✓ Remediation plan created with timelines
- ✓ Audit-ready report generated
- ✓ Stakeholders briefed on findings

---

## Best Practices

### Pre-Audit Preparation

1. **Understand Requirements**: Deep dive into framework documentation
2. **Gather Documentation**: Policies, procedures, architecture diagrams
3. **Identify Stakeholders**: Compliance, security, engineering teams
4. **Define Scope**: Clearly document what's in/out of scope

### During Audit

1. **Document Everything**: Screenshots, code snippets, configuration files
2. **Ask Questions**: Clarify ambiguous requirements with auditors
3. **Be Objective**: Don't hide findings, document accurately
4. **Track Evidence**: Maintain clear evidence trail

### Post-Audit

1. **Prioritize Remediation**: Start with critical gaps
2. **Track Progress**: Regular status updates on remediation
3. **Re-test**: Verify fixes actually close gaps
4. **Continuous Monitoring**: Don't wait for next audit

---

## References

### PCI-DSS
- [PCI-DSS v4.0 Standard](https://www.pcisecuritystandards.org/)
- [PCI SAQ (Self-Assessment Questionnaire)](https://www.pcisecuritystandards.org/)

### HIPAA
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/)
- [NIST HIPAA Security Guidance](https://csrc.nist.gov/publications/detail/sp/800-66/rev-2/final)

### SOC 2
- [AICPA Trust Services Criteria](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/trustdataintegritytaskforce.html)
- [SOC 2 Compliance Guide](https://www.aicpa.org/)

### GDPR
- [GDPR Full Text](https://gdpr-info.eu/)
- [EDPB Guidelines](https://edpb.europa.eu/our-work-tools/general-guidance/gdpr-guidelines-recommendations-best-practices_en)

---

## Related Workflows

- [Complete Security Review](secure-code-review.md)
- [Quick Scan](quick-scan.md)
- [Vulnerability Triage](vulnerability-triage.md)
