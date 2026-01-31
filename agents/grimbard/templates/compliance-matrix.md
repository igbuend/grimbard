# Compliance Control Matrix

## Document Information

**Framework**: {{COMPLIANCE_FRAMEWORK}}
**Framework Version**: {{FRAMEWORK_VERSION}}
**Application**: {{PROJECT_NAME}}
**Application Version**: {{VERSION}}
**Audit Date**: {{AUDIT_DATE}}
**Auditor**: {{AUDITOR_NAME}}
**Audit Scope**: {{AUDIT_SCOPE}}

---

## Executive Summary

### Compliance Status Overview

| Status | Control Count | Percentage |
|--------|---------------|------------|
| ✅ **Fully Compliant** | {{COMPLIANT_COUNT}} | {{COMPLIANT_PERCENT}}% |
| ⚠️ **Partially Compliant** | {{PARTIAL_COUNT}} | {{PARTIAL_PERCENT}}% |
| ❌ **Non-Compliant** | {{NONCOMPLIANT_COUNT}} | {{NONCOMPLIANT_PERCENT}}% |
| ℹ️ **Not Applicable** | {{NA_COUNT}} | {{NA_PERCENT}}% |
| **TOTAL CONTROLS** | **{{TOTAL_CONTROLS}}** | 100% |

### Overall Compliance Score: {{COMPLIANCE_SCORE}}%

### Audit Opinion: {{AUDIT_OPINION}}

---

## Control Assessment Summary

### Critical Non-Compliance Issues

{{CRITICAL_ISSUES_COUNT}} critical control(s) not met:

1. **{{CRITICAL_1_ID}}** - {{CRITICAL_1_TITLE}}
2. **{{CRITICAL_2_ID}}** - {{CRITICAL_2_TITLE}}
3. **{{CRITICAL_3_ID}}** - {{CRITICAL_3_TITLE}}

### Major Gaps

{{MAJOR_GAPS_COUNT}} major gap(s) requiring attention:

1. {{GAP_1}}
2. {{GAP_2}}
3. {{GAP_3}}

---

## Framework-Specific Control Matrix

### {{FRAMEWORK}} Controls

---

#### Domain 1: {{DOMAIN_1_NAME}}

##### Control {{CONTROL_1_ID}}: {{CONTROL_1_TITLE}}

**Requirement**: {{CONTROL_1_REQUIREMENT}}

**Status**: {{CONTROL_1_STATUS}} ✅/⚠️/❌

**Implementation Evidence**:

| Evidence Type | Location | Description |
|---------------|----------|-------------|
| Code | {{CONTROL_1_CODE_LOC}} | {{CONTROL_1_CODE_DESC}} |
| Configuration | {{CONTROL_1_CONFIG_LOC}} | {{CONTROL_1_CONFIG_DESC}} |
| Documentation | {{CONTROL_1_DOC_LOC}} | {{CONTROL_1_DOC_DESC}} |

**SARIF Findings**:
- {{CONTROL_1_FINDING_1}}
- {{CONTROL_1_FINDING_2}}

**Assessment Notes**: {{CONTROL_1_NOTES}}

**Gap Analysis**: {{CONTROL_1_GAP}}

**Remediation Required**: {{CONTROL_1_REMEDIATION}}

**Timeline**: {{CONTROL_1_TIMELINE}}

---

##### Control {{CONTROL_2_ID}}: {{CONTROL_2_TITLE}}

[Repeat structure for each control...]

---

#### Domain 2: {{DOMAIN_2_NAME}}

[Repeat for each domain...]

---

## PCI-DSS v4.0 Specific Controls

*(If Framework = PCI-DSS)*

### Requirement 1: Install and Maintain Network Security Controls

#### Control 1.2.1: Configuration standards for NSCs are defined and implemented

**Status**: {{PCI_1_2_1_STATUS}}
**Evidence**: {{PCI_1_2_1_EVIDENCE}}
**Findings**: {{PCI_1_2_1_FINDINGS}}

### Requirement 3: Protect Stored Account Data

#### Control 3.3.1: Sensitive authentication data (SAD) is not retained after authorization

**Status**: {{PCI_3_3_1_STATUS}}

**Code Review Evidence**:
```
No instances of CVV, PIN, or full track data storage found
Gitleaks scan: 0 findings related to card data
```

**SARIF Findings**: {{PCI_3_3_1_FINDINGS}}

#### Control 3.4.1: PAN is rendered unreadable wherever stored

**Status**: {{PCI_3_4_1_STATUS}}

**Evidence**:
- Encryption: {{PCI_3_4_1_ENCRYPTION}}
- Hashing: {{PCI_3_4_1_HASHING}}
- Tokenization: {{PCI_3_4_1_TOKENIZATION}}

**Code Location**: {{PCI_3_4_1_CODE_LOC}}

### Requirement 4: Protect Cardholder Data with Strong Cryptography During Transmission

#### Control 4.2.1: Strong cryptography and security protocols are implemented

**Status**: {{PCI_4_2_1_STATUS}}

**TLS Configuration**:
- Version: {{PCI_4_2_1_TLS_VERSION}}
- Cipher Suites: {{PCI_4_2_1_CIPHERS}}
- Weak Protocols: {{PCI_4_2_1_WEAK_PROTOCOLS}}

**KICS Findings**: {{PCI_4_2_1_KICS_FINDINGS}}

### Requirement 6: Develop and Maintain Secure Systems and Software

#### Control 6.2.4: Vulnerabilities are addressed via risk-based approach

**Status**: {{PCI_6_2_4_STATUS}}

**Vulnerability Management**:
- Critical Vulnerabilities: {{PCI_6_2_4_CRITICAL}}
- High Vulnerabilities: {{PCI_6_2_4_HIGH}}
- Patch SLA: {{PCI_6_2_4_SLA}}

**OSV-Scanner Findings**: {{PCI_6_2_4_OSV_FINDINGS}}
**Depscan Results**: {{PCI_6_2_4_DEPSCAN}}

### Requirement 8: Identify Users and Authenticate Access

#### Control 8.3.1: MFA is implemented for all access

**Status**: {{PCI_8_3_1_STATUS}}

**Code Evidence**: {{PCI_8_3_1_CODE}}

**Opengrep Findings**: {{PCI_8_3_1_OPENGREP}}

### Requirement 10: Log and Monitor All Access

#### Control 10.2.1: Audit logs capture all individual access

**Status**: {{PCI_10_2_1_STATUS}}

**Logging Coverage**:
- Authentication events: {{PCI_10_2_1_AUTH_LOGGING}}
- Authorization events: {{PCI_10_2_1_AUTHZ_LOGGING}}
- Data access: {{PCI_10_2_1_DATA_LOGGING}}

---

## HIPAA Security Rule Controls

*(If Framework = HIPAA)*

### 164.312(a)(1) - Access Control

#### Unique User Identification (R)

**Status**: {{HIPAA_USER_ID_STATUS}}
**Evidence**: {{HIPAA_USER_ID_EVIDENCE}}
**Findings**: {{HIPAA_USER_ID_FINDINGS}}

#### Emergency Access Procedure (R)

**Status**: {{HIPAA_EMERGENCY_STATUS}}
**Evidence**: {{HIPAA_EMERGENCY_EVIDENCE}}

#### Automatic Logoff (A)

**Status**: {{HIPAA_LOGOFF_STATUS}}
**Evidence**: {{HIPAA_LOGOFF_EVIDENCE}}

#### Encryption and Decryption (A)

**Status**: {{HIPAA_ENCRYPTION_STATUS}}
**Evidence**: {{HIPAA_ENCRYPTION_EVIDENCE}}
**Code Location**: {{HIPAA_ENCRYPTION_CODE}}

### 164.312(b) - Audit Controls

**Status**: {{HIPAA_AUDIT_STATUS}}

**Audit Logging Evidence**:
- ePHI access logged: {{HIPAA_AUDIT_EPHI_LOGGING}}
- Audit log retention: {{HIPAA_AUDIT_RETENTION}}
- Log protection: {{HIPAA_AUDIT_PROTECTION}}

**Opengrep Findings**: {{HIPAA_AUDIT_FINDINGS}}

### 164.312(c) - Integrity

#### Mechanism to Authenticate ePHI (A)

**Status**: {{HIPAA_INTEGRITY_STATUS}}
**Evidence**: {{HIPAA_INTEGRITY_EVIDENCE}}

### 164.312(d) - Person or Entity Authentication

**Status**: {{HIPAA_PERSON_AUTH_STATUS}}
**Evidence**: {{HIPAA_PERSON_AUTH_EVIDENCE}}

### 164.312(e) - Transmission Security

#### Integrity Controls (A)

**Status**: {{HIPAA_TRANS_INTEGRITY_STATUS}}

#### Encryption (A)

**Status**: {{HIPAA_TRANS_ENCRYPTION_STATUS}}

**TLS Implementation**:
- HTTPS enforced: {{HIPAA_HTTPS_ENFORCED}}
- TLS version: {{HIPAA_TLS_VERSION}}
- No plaintext PHI: {{HIPAA_NO_PLAINTEXT}}

**KICS Findings**: {{HIPAA_KICS_FINDINGS}}

---

## SOC 2 Trust Service Criteria

*(If Framework = SOC2)*

### CC6.1 - Logical and Physical Access Controls

**Status**: {{SOC2_CC61_STATUS}}

**Implementation**:
- Authentication: {{SOC2_CC61_AUTH}}
- Authorization: {{SOC2_CC61_AUTHZ}}
- Access review: {{SOC2_CC61_REVIEW}}

**Code Evidence**: {{SOC2_CC61_CODE}}
**Findings**: {{SOC2_CC61_FINDINGS}}

### CC6.6 - Protection of Confidential Information

**Status**: {{SOC2_CC66_STATUS}}

**Encryption Implementation**:
- At rest: {{SOC2_CC66_AT_REST}}
- In transit: {{SOC2_CC66_IN_TRANSIT}}
- Key management: {{SOC2_CC66_KEY_MGMT}}

**Application Inspector Results**: {{SOC2_CC66_APPINSP}}

### CC7.2 - System Monitoring

**Status**: {{SOC2_CC72_STATUS}}

**Monitoring Capabilities**:
- Security events: {{SOC2_CC72_SEC_EVENTS}}
- Performance: {{SOC2_CC72_PERFORMANCE}}
- Availability: {{SOC2_CC72_AVAILABILITY}}

**Code Evidence**: {{SOC2_CC72_CODE}}

### CC8.1 - Vulnerability Management

**Status**: {{SOC2_CC81_STATUS}}

**Vulnerability Scanning**:
- Scan frequency: {{SOC2_CC81_FREQUENCY}}
- Critical findings: {{SOC2_CC81_CRITICAL}}
- Remediation SLA: {{SOC2_CC81_SLA}}

**Tool Results**:
- Opengrep: {{SOC2_CC81_OPENGREP}}
- OSV-Scanner: {{SOC2_CC81_OSV}}
- Depscan: {{SOC2_CC81_DEPSCAN}}

---

## GDPR Requirements

*(If Framework = GDPR)*

### Article 25 - Data Protection by Design and by Default

**Status**: {{GDPR_ART25_STATUS}}

**Implementation Evidence**:
- Data minimization: {{GDPR_ART25_MINIMIZATION}}
- Privacy by default: {{GDPR_ART25_DEFAULT}}
- Pseudonymization: {{GDPR_ART25_PSEUDO}}

**Code Review**: {{GDPR_ART25_CODE}}

### Article 32 - Security of Processing

**Status**: {{GDPR_ART32_STATUS}}

**Security Measures**:
- Encryption: {{GDPR_ART32_ENCRYPTION}}
- Confidentiality: {{GDPR_ART32_CONFIDENTIALITY}}
- Integrity: {{GDPR_ART32_INTEGRITY}}
- Availability: {{GDPR_ART32_AVAILABILITY}}
- Resilience: {{GDPR_ART32_RESILIENCE}}

**SARIF Findings**: {{GDPR_ART32_FINDINGS}}

### Article 33 - Notification of Personal Data Breach

**Status**: {{GDPR_ART33_STATUS}}

**Breach Detection Capabilities**:
- Detection mechanisms: {{GDPR_ART33_DETECTION}}
- Notification procedure: {{GDPR_ART33_NOTIFICATION}}
- Documentation: {{GDPR_ART33_DOCUMENTATION}}

### Article 35 - Data Protection Impact Assessment

**Status**: {{GDPR_ART35_STATUS}}

**DPIA Evidence**: {{GDPR_ART35_DPIA}}

---

## Gap Analysis

### Critical Gaps Requiring Immediate Attention

| Control ID | Control Title | Gap Description | Remediation | Timeline | Owner |
|------------|---------------|-----------------|-------------|----------|-------|
| {{GAP_1_ID}} | {{GAP_1_TITLE}} | {{GAP_1_DESC}} | {{GAP_1_REMEDIATION}} | {{GAP_1_TIMELINE}} | {{GAP_1_OWNER}} |
| {{GAP_2_ID}} | {{GAP_2_TITLE}} | {{GAP_2_DESC}} | {{GAP_2_REMEDIATION}} | {{GAP_2_TIMELINE}} | {{GAP_2_OWNER}} |

### Partial Compliance Items

| Control ID | Current State | Required State | Actions Needed |
|------------|---------------|----------------|----------------|
| {{PARTIAL_1_ID}} | {{PARTIAL_1_CURRENT}} | {{PARTIAL_1_REQUIRED}} | {{PARTIAL_1_ACTIONS}} |
| {{PARTIAL_2_ID}} | {{PARTIAL_2_CURRENT}} | {{PARTIAL_2_REQUIRED}} | {{PARTIAL_2_ACTIONS}} |

---

## Remediation Roadmap

### Phase 1: Critical Compliance (0-30 days)

**Objective**: Address all non-compliant critical controls

**Actions**:
1. {{PHASE1_ACTION_1}}
2. {{PHASE1_ACTION_2}}
3. {{PHASE1_ACTION_3}}

**Resources**: {{PHASE1_RESOURCES}}
**Estimated Effort**: {{PHASE1_EFFORT}} engineer-days

### Phase 2: Full Compliance (1-3 months)

**Objective**: Achieve 100% compliance for all applicable controls

**Actions**:
1. {{PHASE2_ACTION_1}}
2. {{PHASE2_ACTION_2}}
3. {{PHASE2_ACTION_3}}

**Resources**: {{PHASE2_RESOURCES}}
**Estimated Effort**: {{PHASE2_EFFORT}} engineer-days

### Phase 3: Continuous Compliance (Ongoing)

**Objective**: Maintain compliance through continuous monitoring

**Actions**:
1. {{PHASE3_ACTION_1}}
2. {{PHASE3_ACTION_2}}
3. {{PHASE3_ACTION_3}}

---

## Evidence Inventory

### Code-Based Evidence

| Control | Evidence Type | Location | Description |
|---------|---------------|----------|-------------|
| {{EVIDENCE_1_CONTROL}} | {{EVIDENCE_1_TYPE}} | {{EVIDENCE_1_LOC}} | {{EVIDENCE_1_DESC}} |
| {{EVIDENCE_2_CONTROL}} | {{EVIDENCE_2_TYPE}} | {{EVIDENCE_2_LOC}} | {{EVIDENCE_2_DESC}} |

### SARIF Evidence

All security findings mapped to compliance controls:

- `consolidated.sarif` - Complete findings
- `compliance-mappings.json` - Finding → Control mapping
- Tool-specific SARIF files in `./sarif/` directory

### Documentation Evidence

- Security policies: {{DOC_POLICIES_LOC}}
- Procedures: {{DOC_PROCEDURES_LOC}}
- Training records: {{DOC_TRAINING_LOC}}
- Incident response plan: {{DOC_INCIDENT_LOC}}

---

## Attestation

### Auditor Statement

I have conducted a security code review of {{PROJECT_NAME}} against {{COMPLIANCE_FRAMEWORK}} {{FRAMEWORK_VERSION}} requirements on {{AUDIT_DATE}}.

**Methodology**:
- Automated security scanning (8 tools)
- Manual code review
- Configuration review
- Documentation review

**Conclusion**: {{AUDITOR_CONCLUSION}}

**Recommendations**: {{AUDITOR_RECOMMENDATIONS}}

**Signature**: {{AUDITOR_SIGNATURE}}
**Date**: {{ATTESTATION_DATE}}

---

## Appendices

### Appendix A: Control Checklist

Complete checklist of all {{TOTAL_CONTROLS}} controls with status:

[Full control-by-control checklist...]

### Appendix B: SARIF Reports

Location: `./compliance-audit/sarif/`

### Appendix C: Remediation Details

Detailed remediation guidance for each gap.

### Appendix D: Tool Configurations

Security scanning tool configurations used.

---

**Report Generated**: {{GENERATION_DATE}}
**Next Audit**: {{NEXT_AUDIT_DATE}}
**Document Version**: {{DOCUMENT_VERSION}}
