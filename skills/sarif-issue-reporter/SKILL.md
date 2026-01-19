```yaml
name: sarif-issue-reporter
version: 0.0.1
description: Verify and report security issues from SARIF files with comprehensive analysis including CVSS scoring, impact assessment, exploitation scenarios, and remediation guidance
author: Herman Stevens
tags: [security, sarif, vulnerability-analysis, reporting, code-review]
related_skills: [code-reviewer, security-patterns, vulnerability-assessment]
```

# SARIF Issue Reporter Skill

## Overview

This skill enables Claude or other AI to analyze SARIF (Static Analysis Results Interchange Format) files, verify reported security issues, and generate comprehensive security reports. Each verified issue includes detailed analysis with CVSS 3.1 scoring, exploitation scenarios, broken security patterns, and remediation guidance linked to industry standards (OWASP, CWE, CAPEC).

## Core Capabilities

1. **SARIF File Parsing**: Read and interpret SARIF 2.1.0 format files
2. **Issue Verification**: Analyze reported findings to confirm validity and severity
3. **Security Scoring**: Calculate CVSS 3.1 scores with detailed vector strings
4. **Impact Analysis**: Assess business and technical impact of vulnerabilities
5. **Exploitation Proof**: Demonstrate how vulnerabilities can be exploited
6. **Pattern Mapping**: Identify violated security patterns and best practices
7. **Standards Mapping**: Link to OWASP Top 10, CWE, CAPEC, and compliance frameworks
8. **Remediation Guidance**: Provide actionable fixes with code examples

## Workflow

### Phase 1: SARIF Analysis
1. Parse SARIF file structure
2. Extract tool metadata and run information
3. Identify all reported issues (results array)
4. Categorize by severity and rule type

### Phase 2: Issue Verification
For each reported issue:
1. **Extract Context**
   - Code location (file, line numbers)
   - Code snippet from physicalLocation/region
   - Data flow paths (codeFlows)
   - Related locations

2. **Verify Finding**
   - Confirm the issue exists in the code
   - Validate the severity assessment
   - Check for false positives
   - Assess exploitability

3. **Enhance Analysis**
   - Request additional code context if needed
   - Analyze surrounding code for defense mechanisms
   - Identify code patterns and anti-patterns

### Phase 3: Security Assessment

#### CVSS 3.1 Scoring
Calculate comprehensive CVSS score considering:
- **Attack Vector (AV)**: Network, Adjacent, Local, Physical
- **Attack Complexity (AC)**: Low, High
- **Privileges Required (PR)**: None, Low, High
- **User Interaction (UI)**: None, Required
- **Scope (S)**: Unchanged, Changed
- **Confidentiality (C)**: None, Low, High
- **Integrity (I)**: None, Low, High
- **Availability (A)**: None, Low, High

Generate vector string: `CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_`

#### Impact Analysis
Assess multiple dimensions:
- **Technical Impact**: Data exposure, system compromise, service disruption
- **Business Impact**: Financial loss, reputation damage, compliance violations
- **Exploitability**: Ease of exploitation, required attacker skill level
- **Affected Assets**: Systems, data types, users impacted

### Phase 4: Standards Mapping

Map each verified issue to:

1. **OWASP Top 10 (2021)**
   - A01:2021 – Broken Access Control
   - A02:2021 – Cryptographic Failures
   - A03:2021 – Injection
   - A04:2021 – Insecure Design
   - A05:2021 – Security Misconfiguration
   - A06:2021 – Vulnerable and Outdated Components
   - A07:2021 – Identification and Authentication Failures
   - A08:2021 – Software and Data Integrity Failures
   - A09:2021 – Security Logging and Monitoring Failures
   - A10:2021 – Server-Side Request Forgery (SSRF)

2. **CWE (Common Weakness Enumeration)**
   - Identify specific CWE ID(s)
   - Link to CWE description
   - Note parent/child relationships

3. **CAPEC (Common Attack Pattern Enumeration)**
   - List applicable attack patterns
   - Describe attack scenarios

4. **OWASP Cheat Sheets**
   - Link to relevant prevention guides
   - Reference specific sections

5. **Compliance/Regulations**
   - PCI-DSS requirements
   - GDPR articles
   - SOC 2 controls
   - HIPAA safeguards
   - ISO 27001 controls
   - NIST frameworks

### Phase 5: Report Generation

For each verified issue, create a structured report:

```markdown
## [ISSUE-XXX] {Title}

**Severity**: {Critical|High|Medium|Low|Info}
**CVSS 3.1 Score**: {Score} ({Vector String})
**Status**: Verified ✓

### Executive Summary
{2-3 sentence overview of the vulnerability}

### Technical Description
{Detailed explanation of the security flaw}

### Code Evidence

**Location**: `{file}:{line}`

```{language}
{code snippet with context}
```

**Data Flow**:
{Trace data flow if available from SARIF codeFlows}

### Exploitation Scenario

**Attack Vector**: {How an attacker would exploit this}

**Proof of Concept**:
```{language}
{Example exploit code or HTTP request}
```

**Prerequisites**: {What attacker needs}
**Expected Outcome**: {What happens when exploited}

### Impact Assessment

**Confidentiality**: {Impact description}
**Integrity**: {Impact description}
**Availability**: {Impact description}

**Business Impact**:
- {Bullet points of business consequences}

### Security Patterns Violated

1. **{Pattern Name}** (from security patterns catalog)
   - Expected: {What should have been done}
   - Actual: {What was done instead}
   - Reference: {Link to pattern documentation}

2. **{Another Pattern}**
   - ...

### Standards & Compliance Mapping

**OWASP Top 10**: {Category} - {Description}
**CWE**: CWE-{ID} - {Name} ({URL})
**CAPEC**: CAPEC-{ID} - {Attack Pattern Name}

**OWASP Cheat Sheets**:
- [{Cheat Sheet Name}]({URL}) - {Relevant Section}

**Compliance Impact**:
- **PCI-DSS**: Requirement {X.X.X}
- **GDPR**: Article {XX}
- **SOC 2**: {Control Category}
- **ISO 27001**: Control {X.X.X}

### Remediation Recommendations

**Priority**: {Immediate|High|Medium|Low}

**Short-term Fix**:
```{language}
{Code showing immediate mitigation}
```

**Long-term Solution**:
```{language}
{Code showing proper implementation}
```

**Implementation Steps**:
1. {Step-by-step remediation}
2. {With specific actions}
3. {And verification methods}

**Security Pattern to Implement**: {Pattern Name}
- {Link to pattern documentation}
- {Key implementation points}

### Validation & Testing

**How to Verify the Fix**:
```{language/bash}
{Test cases or verification commands}
```

**Regression Prevention**:
- {Unit test requirements}
- {SAST rule configurations}
- {Code review checklist items}

### References

**OWASP Resources**:
- {Links to relevant OWASP documentation}

**CWE/CAPEC**:
- {Links to CWE/CAPEC entries}

**Security Patterns**:
- {Links to pattern documentation}

**Additional Resources**:
- {Other helpful references}

---
```

## Implementation Instructions

### When Using This Skill

1. **Initial SARIF Loading**
   ```bash
   # Parse the SARIF file
   python -c "import json; print(json.dumps(json.load(open('results.sarif')), indent=2))"
   ```

2. **Verification Process**
   - For each issue in `runs[].results[]`:
     - Extract rule ID and message
     - Get physical location
     - Retrieve code snippet (if not in SARIF, read from file)
     - Analyze in context

3. **Code Context Retrieval**
   ```python
   # If code snippet not in SARIF
   with open(file_path) as f:
       lines = f.readlines()
       start = max(0, line_number - 5)
       end = min(len(lines), line_number + 5)
       context = ''.join(lines[start:end])
   ```

4. **CVSS Calculation**
   - Use the CVSS calculator logic
   - Document all metric choices
   - Provide both Base and Temporal scores if applicable

5. **Pattern Matching**
   - Cross-reference with Herman's security patterns repository
   - Identify which patterns were violated
   - Note which patterns should have been applied

### Report Output Formats

**Primary Format**: Markdown document
**Alternate Formats**:
- JSON (structured data)
- HTML (for web viewing)
- PDF (executive reports)
- CSV (for tracking/metrics)

### Quality Checks

Before finalizing each issue report:
- ✓ CVSS score calculated and justified
- ✓ Code evidence included with context
- ✓ Exploitation scenario is realistic
- ✓ At least one security pattern identified
- ✓ Mapped to OWASP Top 10
- ✓ CWE and CAPEC referenced
- ✓ Remediation code provided
- ✓ References are accurate and accessible

## SARIF Structure Reference

```json
{
  "version": "2.1.0",
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "runs": [{
    "tool": {
      "driver": {
        "name": "ToolName",
        "version": "1.0.0",
        "rules": [{
          "id": "RULE-001",
          "shortDescription": { "text": "..." },
          "fullDescription": { "text": "..." },
          "help": { "text": "..." }
        }]
      }
    },
    "results": [{
      "ruleId": "RULE-001",
      "level": "error|warning|note",
      "message": { "text": "..." },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": "file.js" },
          "region": {
            "startLine": 42,
            "startColumn": 10,
            "snippet": { "text": "..." }
          }
        }
      }],
      "codeFlows": [...],
      "relatedLocations": [...]
    }]
  }]
}
```

## Example Usage

**User Request**:
"Analyze this SARIF file and generate a security report for all critical and high severity issues"

**Claude Response**:
1. Parse SARIF file
2. Filter issues by severity (critical/high)
3. For each issue:
   - Verify the finding
   - Calculate CVSS score
   - Generate comprehensive report
4. Output consolidated report with all verified issues

## Best Practices

1. **Always Verify**: Don't blindly trust SARIF findings - verify in code context
2. **Realistic Exploitation**: Ensure exploitation scenarios are practical, not theoretical
3. **Actionable Remediation**: Provide code that can actually be implemented
4. **Complete Mapping**: Link to all relevant standards and frameworks
5. **Context Matters**: Include sufficient code context to understand the issue
6. **Pattern-Based**: Always reference violated security patterns
7. **Compliance Aware**: Consider regulatory requirements in impact assessment

## Integration Points

### With Security Patterns Repository
- Reference patterns from `D:\github\patterns\skills\`
- Link to pattern documentation
- Show pattern implementation examples

### With Code Review Skills
- Use similar verification techniques
- Apply code quality assessment
- Check for defensive programming

### With Compliance Frameworks
- Map to specific requirements
- Generate compliance reports
- Track remediation progress

## Output Templates

### Executive Summary Template
```markdown
# Security Analysis Report

**Scan Date**: {date}
**Tool**: {SARIF tool name and version}
**Scope**: {files/components scanned}

## Overview
- **Total Issues Found**: {count}
- **Verified Issues**: {count}
- **False Positives**: {count}

### Severity Distribution
- Critical: {count} (CVSS 9.0-10.0)
- High: {count} (CVSS 7.0-8.9)
- Medium: {count} (CVSS 4.0-6.9)
- Low: {count} (CVSS 0.1-3.9)

### Top Risks
1. {Issue title} - CVSS {score}
2. {Issue title} - CVSS {score}
3. {Issue title} - CVSS {score}

## Detailed Findings
{Individual issue reports follow}
```

## Anti-Patterns to Avoid

1. ❌ Reporting unverified issues
2. ❌ Generic remediation advice
3. ❌ Missing exploitation scenarios
4. ❌ Incomplete CVSS justification
5. ❌ Ignoring code context
6. ❌ Missing compliance mapping

## Success Criteria

A successful report includes:
- ✅ All critical/high issues verified
- ✅ CVSS scores with full justification
- ✅ Working exploitation examples
- ✅ Code-level remediation
- ✅ Security pattern references
- ✅ Complete standards mapping
- ✅ Actionable next steps

## Notes for Claude

When using this skill:
- Take time to thoroughly verify each issue
- Don't rush the CVSS calculation - justify each metric
- Provide realistic, not just theoretical, exploitation scenarios
- Reference security patterns when applicable
- Make remediation code production-ready, not pseudo-code
- Link to official documentation, not generic advice
- Consider the full application context, not just the isolated code snippet

## Version History

- **0.0.1** (2025-01-18): Initial skill creation with comprehensive SARIF analysis, CVSS scoring, and multi-framework mapping capabilities
