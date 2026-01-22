# Security Finding: {{FINDING_ID}}

## Finding Metadata

| Field | Value |
|-------|-------|
| **Finding ID** | {{FINDING_ID}} |
| **Title** | {{FINDING_TITLE}} |
| **Severity** | {{SEVERITY}} ({{SEVERITY_EMOJI}}) |
| **Priority** | {{PRIORITY}} |
| **Status** | {{STATUS}} |
| **Detected By** | {{TOOL_NAME}} |
| **Detection Date** | {{DETECTION_DATE}} |
| **Assigned To** | {{ASSIGNEE}} |
| **Target Fix Date** | {{TARGET_FIX_DATE}} |

---

## Classification

| Category | Value |
|----------|-------|
| **CWE** | [CWE-{{CWE_ID}}: {{CWE_TITLE}}](https://cwe.mitre.org/data/definitions/{{CWE_ID}}.html) |
| **OWASP** | {{OWASP_CATEGORY}} |
| **CAPEC** | {{CAPEC_ID}} (if applicable) |
| **CVSS Score** | {{CVSS_SCORE}} ({{CVSS_SEVERITY}}) |
| **Exploitability** | {{EXPLOITABILITY}} (Low/Medium/High) |
| **False Positive** | {{FALSE_POSITIVE}} (Yes/No/Unknown) |

---

## Location

### Primary Location

**File**: `{{FILE_PATH}}`
**Line**: {{LINE_NUMBER}}
**Column**: {{COLUMN_NUMBER}} (if available)
**Function/Method**: `{{FUNCTION_NAME}}`
**Class**: `{{CLASS_NAME}}` (if applicable)

### Related Locations

Additional affected code locations:

1. `{{RELATED_FILE_1}}:{{RELATED_LINE_1}}` - {{RELATED_DESC_1}}
2. `{{RELATED_FILE_2}}:{{RELATED_LINE_2}}` - {{RELATED_DESC_2}}

### Git Information

**Branch**: {{GIT_BRANCH}}
**Commit**: {{GIT_COMMIT_HASH}}
**Author**: {{GIT_AUTHOR}}
**Commit Date**: {{GIT_COMMIT_DATE}}

---

## Vulnerability Description

### Summary

{{VULNERABILITY_SUMMARY}}

### Detailed Description

{{DETAILED_DESCRIPTION}}

### Root Cause

{{ROOT_CAUSE_ANALYSIS}}

---

## Vulnerable Code

### Current Code

**Language**: {{CODE_LANGUAGE}}
**Context**: {{CODE_CONTEXT}}

```{{CODE_LANGUAGE}}
{{VULNERABLE_CODE_SNIPPET}}
```

### Code Flow

The vulnerability occurs through this execution path:

1. {{FLOW_STEP_1}}
2. {{FLOW_STEP_2}}
3. {{FLOW_STEP_3}}

**Data Flow**: {{DATA_FLOW_DESCRIPTION}}

---

## Impact Analysis

### Security Impact

**Confidentiality**: {{IMPACT_CONFIDENTIALITY}} (None/Low/Medium/High)
**Integrity**: {{IMPACT_INTEGRITY}} (None/Low/Medium/High)
**Availability**: {{IMPACT_AVAILABILITY}} (None/Low/Medium/High)

### Business Impact

{{BUSINESS_IMPACT_DESCRIPTION}}

**Potential Consequences**:

- ❌ {{CONSEQUENCE_1}}
- ❌ {{CONSEQUENCE_2}}
- ❌ {{CONSEQUENCE_3}}

### Affected Components

- {{AFFECTED_COMPONENT_1}}
- {{AFFECTED_COMPONENT_2}}
- {{AFFECTED_COMPONENT_3}}

### Affected Users/Data

**User Impact**: {{USER_IMPACT}}
**Data at Risk**: {{DATA_AT_RISK}}
**Scale**: {{IMPACT_SCALE}} (Single user/Multiple users/All users)

---

## Exploitation

### Attack Scenario

{{ATTACK_SCENARIO_DESCRIPTION}}

### Prerequisites

Attacker needs:

- {{PREREQUISITE_1}}
- {{PREREQUISITE_2}}
- {{PREREQUISITE_3}}

### Attack Complexity

**Complexity**: {{ATTACK_COMPLEXITY}} (Low/Medium/High)
**Required Privileges**: {{REQUIRED_PRIVILEGES}} (None/Low/High)
**User Interaction**: {{USER_INTERACTION}} (None/Required)

### Proof of Concept

{{POC_DESCRIPTION}}

```{{POC_LANGUAGE}}
{{PROOF_OF_CONCEPT_CODE}}
```

**Steps to Reproduce**:

1. {{REPRODUCTION_STEP_1}}
2. {{REPRODUCTION_STEP_2}}
3. {{REPRODUCTION_STEP_3}}

**Expected Result**: {{EXPLOITATION_EXPECTED_RESULT}}

---

## Remediation

### Recommended Fix

**Fix Strategy**: {{FIX_STRATEGY}}

**Fixed Code**:

```{{CODE_LANGUAGE}}
{{FIXED_CODE_SNIPPET}}
```

### Implementation Steps

1. **{{STEP_1_TITLE}}**
   {{STEP_1_DESCRIPTION}}

2. **{{STEP_2_TITLE}}**
   {{STEP_2_DESCRIPTION}}

3. **{{STEP_3_TITLE}}**
   {{STEP_3_DESCRIPTION}}

### Additional Security Measures

Beyond fixing this specific instance:

- ✅ {{ADDITIONAL_MEASURE_1}}
- ✅ {{ADDITIONAL_MEASURE_2}}
- ✅ {{ADDITIONAL_MEASURE_3}}

### Dependencies

This fix requires:

- {{DEPENDENCY_1}}
- {{DEPENDENCY_2}}

### Effort Estimate

**Estimated Time**: {{EFFORT_ESTIMATE}} (hours/days)
**Complexity**: {{FIX_COMPLEXITY}} (Low/Medium/High)
**Risk**: {{FIX_RISK}} (Low/Medium/High)

---

## Testing and Verification

### Verification Steps

1. **{{VERIFICATION_STEP_1_TITLE}}**
   {{VERIFICATION_STEP_1_DESCRIPTION}}
   **Expected**: {{VERIFICATION_STEP_1_EXPECTED}}

2. **{{VERIFICATION_STEP_2_TITLE}}**
   {{VERIFICATION_STEP_2_DESCRIPTION}}
   **Expected**: {{VERIFICATION_STEP_2_EXPECTED}}

3. **{{VERIFICATION_STEP_3_TITLE}}**
   {{VERIFICATION_STEP_3_DESCRIPTION}}
   **Expected**: {{VERIFICATION_STEP_3_EXPECTED}}

### Unit Tests

Add these tests to prevent regression:

```{{TEST_LANGUAGE}}
{{UNIT_TEST_CODE}}
```

### Integration Tests

```{{TEST_LANGUAGE}}
{{INTEGRATION_TEST_CODE}}
```

### Security Tests

```{{TEST_LANGUAGE}}
{{SECURITY_TEST_CODE}}
```

---

## Tool Output

### SARIF Details

**Rule ID**: {{RULE_ID}}
**Rule Name**: {{RULE_NAME}}
**Message**: {{RULE_MESSAGE}}
**Help URL**: {{RULE_HELP_URL}}

**SARIF Level**: {{SARIF_LEVEL}} (error/warning/note/none)
**Confidence**: {{CONFIDENCE}} (Low/Medium/High)

### Raw Tool Output

```
{{RAW_TOOL_OUTPUT}}
```

---

## Related Findings

### Similar Patterns

This finding is similar to:

- {{RELATED_FINDING_1}} - {{RELATED_FINDING_1_LOC}}
- {{RELATED_FINDING_2}} - {{RELATED_FINDING_2_LOC}}

### Variant Analysis

Search for similar patterns in:

```bash
# Example search command
opengrep -e '{{PATTERN}}' -lang {{LANGUAGE}} /path/to/project
```

---

## References

### CWE Reference

**CWE-{{CWE_ID}}**: {{CWE_TITLE}}
**URL**: https://cwe.mitre.org/data/definitions/{{CWE_ID}}.html
**Description**: {{CWE_DESCRIPTION}}

### OWASP Reference

**Category**: {{OWASP_CATEGORY}}
**URL**: {{OWASP_URL}}
**Mitigation**: {{OWASP_MITIGATION}}

### Security Best Practices

- [{{REFERENCE_1_TITLE}}]({{REFERENCE_1_URL}})
- [{{REFERENCE_2_TITLE}}]({{REFERENCE_2_URL}})
- [{{REFERENCE_3_TITLE}}]({{REFERENCE_3_URL}})

### Tool Documentation

- [{{TOOL_NAME}} - {{RULE_NAME}}]({{TOOL_RULE_URL}})

---

## Compliance Mapping

### PCI-DSS

**Requirement**: {{PCI_REQUIREMENT}}
**Control**: {{PCI_CONTROL}}
**Impact**: {{PCI_IMPACT}}

### HIPAA

**Requirement**: {{HIPAA_REQUIREMENT}}
**Impact**: {{HIPAA_IMPACT}}

### SOC 2

**Trust Criteria**: {{SOC2_CRITERIA}}
**Impact**: {{SOC2_IMPACT}}

### GDPR

**Article**: {{GDPR_ARTICLE}}
**Impact**: {{GDPR_IMPACT}}

---

## Timeline

| Date | Event | Details |
|------|-------|---------|
| {{DETECTION_DATE}} | Detected | Found by {{TOOL_NAME}} |
| {{TRIAGE_DATE}} | Triaged | Priority {{PRIORITY}} assigned |
| {{ASSIGNED_DATE}} | Assigned | Assigned to {{ASSIGNEE}} |
| {{TARGET_FIX_DATE}} | Target Fix | SLA deadline |
| {{ACTUAL_FIX_DATE}} | Fixed | (pending) |
| {{VERIFICATION_DATE}} | Verified | (pending) |
| {{DEPLOYMENT_DATE}} | Deployed | (pending) |

---

## Communication

### Stakeholders Notified

- {{STAKEHOLDER_1}} - {{STAKEHOLDER_1_ROLE}} - Notified {{STAKEHOLDER_1_DATE}}
- {{STAKEHOLDER_2}} - {{STAKEHOLDER_2_ROLE}} - Notified {{STAKEHOLDER_2_DATE}}

### Security Advisory

**Advisory ID**: {{ADVISORY_ID}}
**Published**: {{ADVISORY_DATE}}
**Audience**: {{ADVISORY_AUDIENCE}}

---

## Comments and Notes

### Triage Notes

{{TRIAGE_NOTES}}

### Developer Notes

{{DEVELOPER_NOTES}}

### Security Team Notes

{{SECURITY_TEAM_NOTES}}

### Change History

| Date | Author | Change |
|------|--------|--------|
| {{CHANGE_1_DATE}} | {{CHANGE_1_AUTHOR}} | {{CHANGE_1_DESCRIPTION}} |
| {{CHANGE_2_DATE}} | {{CHANGE_2_AUTHOR}} | {{CHANGE_2_DESCRIPTION}} |

---

## Attachments

- {{ATTACHMENT_1_NAME}} - {{ATTACHMENT_1_DESCRIPTION}}
- {{ATTACHMENT_2_NAME}} - {{ATTACHMENT_2_DESCRIPTION}}

---

## Resolution

### Fix Implementation

**Fixed By**: {{FIXED_BY}}
**Fix Date**: {{FIX_DATE}}
**Fix Commit**: {{FIX_COMMIT_HASH}}
**Fix Description**: {{FIX_DESCRIPTION}}

### Verification Results

**Verified By**: {{VERIFIED_BY}}
**Verification Date**: {{VERIFICATION_DATE}}
**Verification Status**: {{VERIFICATION_STATUS}} (Pass/Fail)
**Verification Notes**: {{VERIFICATION_NOTES}}

### Deployment

**Deployed To**: {{DEPLOYED_TO}}
**Deployment Date**: {{DEPLOYMENT_DATE}}
**Deployment Version**: {{DEPLOYMENT_VERSION}}

### Closure

**Status**: {{FINAL_STATUS}} (Fixed/Won't Fix/False Positive/Duplicate)
**Closed By**: {{CLOSED_BY}}
**Closure Date**: {{CLOSURE_DATE}}
**Closure Reason**: {{CLOSURE_REASON}}

---

**Document Version**: {{DOCUMENT_VERSION}}
**Last Updated**: {{LAST_UPDATED}}
**Next Review**: {{NEXT_REVIEW_DATE}}
