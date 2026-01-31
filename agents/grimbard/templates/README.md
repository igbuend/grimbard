# Grimbard Report Templates

This directory contains templates for generating professional security reports from workflow outputs.

## Available Templates

### 1. Executive Summary (`executive-summary.md`)

**Purpose**: High-level overview for management and executives

**Audience**: C-level executives, VPs, directors, product managers

**Length**: 1-2 pages

**Contains**:
- Overall security posture summary
- Key metrics (findings count by severity)
- Top risks and critical findings
- Remediation timeline and resource requirements
- Business impact assessment

**Use When**: Presenting to non-technical stakeholders who need security overview

---

### 2. Technical Findings Report (`technical-findings.md`)

**Purpose**: Detailed technical vulnerability analysis for engineers

**Audience**: Software engineers, security engineers, DevOps teams

**Length**: 10-50 pages (depending on findings)

**Contains**:
- Detailed finding descriptions
- Code locations and snippets
- Exploitation scenarios
- Step-by-step remediation guidance
- Testing/verification procedures

**Use When**: Providing actionable remediation guidance to development teams

---

### 3. Compliance Matrix (`compliance-matrix.md`)

**Purpose**: Map security findings to compliance framework controls

**Audience**: Compliance officers, auditors, security architects

**Length**: 5-15 pages

**Contains**:
- Control-by-control compliance status
- Evidence mapping (code → control)
- Gap analysis
- Remediation roadmap
- Audit trail documentation

**Use When**: Preparing for compliance audits (PCI-DSS, HIPAA, SOC 2, GDPR)

---

### 4. Finding Detail Template (`finding-template.md`)

**Purpose**: Consistent structure for individual vulnerability findings

**Audience**: All technical audiences

**Contains**:
- Finding ID and severity
- CWE/OWASP classification
- Affected code location
- Vulnerability description
- Proof of concept / exploitation steps
- Remediation guidance
- References

**Use When**: Documenting individual findings consistently

---

## Template Usage

### Using Templates in Workflows

Templates are automatically used by workflows in Phase 6 (Reporting):

```markdown
## Phase 6: Reporting

Use the following templates to generate reports:

1. **Executive Summary**: `templates/executive-summary.md`
2. **Technical Report**: `templates/technical-findings.md`
3. **Compliance Matrix**: `templates/compliance-matrix.md` (if compliance audit)
```

### Manual Template Application

```bash
# Generate executive summary from SARIF findings
python -m sarif_tools summary \
  ./security-review-output/sarif/consolidated.sarif \
  --template ./templates/executive-summary.md \
  > ./security-review-output/reports/executive-summary.md

# Generate technical report
python -m sarif_tools report \
  ./security-review-output/sarif/consolidated.sarif \
  --template ./templates/technical-findings.md \
  > ./security-review-output/reports/technical-report.md
```

### Customizing Templates

Create custom templates by copying and modifying existing ones:

```bash
# Copy template
cp templates/technical-findings.md templates/my-custom-report.md

# Edit template (add custom sections, modify structure)
# Use template in workflow
```

## Template Variables

Templates use these variables (populated by workflow):

### Common Variables

- `{{PROJECT_NAME}}` - Project/repository name
- `{{SCAN_DATE}}` - Date of security scan
- `{{REVIEWER}}` - Name of person conducting review
- `{{VERSION}}` - Application version scanned
- `{{TOTAL_FINDINGS}}` - Total number of findings
- `{{P0_COUNT}}` - Number of P0 (critical) findings
- `{{P1_COUNT}}` - Number of P1 (high) findings
- `{{P2_COUNT}}` - Number of P2 (medium) findings
- `{{P3_COUNT}}` - Number of P3 (low) findings

### Finding-Specific Variables

- `{{FINDING_ID}}` - Unique finding identifier
- `{{SEVERITY}}` - error, warning, note, info
- `{{PRIORITY}}` - P0, P1, P2, P3
- `{{CWE}}` - CWE identifier (e.g., CWE-89)
- `{{OWASP}}` - OWASP Top 10 classification
- `{{FILE_PATH}}` - File containing vulnerability
- `{{LINE_NUMBER}}` - Line number of vulnerability
- `{{CODE_SNIPPET}}` - Affected code
- `{{DESCRIPTION}}` - Vulnerability description
- `{{REMEDIATION}}` - Fix guidance

### Compliance Variables

- `{{FRAMEWORK}}` - PCI-DSS, HIPAA, SOC2, GDPR
- `{{CONTROL_ID}}` - Control identifier
- `{{CONTROL_STATUS}}` - Pass, Fail, Partial
- `{{EVIDENCE}}` - Code evidence for control

## Template Best Practices

### 1. Consistent Structure

All templates should follow a clear hierarchy:

```markdown
# Title
## Executive Summary
## Detailed Sections
## Appendices
```

### 2. Clear Severity Classification

Use consistent severity indicators:

- 🔴 **P0 - Critical**: Immediate action required (24h)
- 🟡 **P1 - High**: Fix before release (1 week)
- 🟢 **P2 - Medium**: Fix in sprint (2 weeks)
- ⚪ **P3 - Low**: Backlog (quarterly)

### 3. Actionable Remediation

Always include:
- What to fix (specific code/configuration)
- How to fix (step-by-step)
- How to verify (testing procedures)
- Timeline (when it should be fixed)

### 4. Evidence-Based

Link findings to evidence:
- Code locations (file:line)
- SARIF rule IDs
- CWE/OWASP classifications
- Tool that detected it

### 5. Audience-Appropriate

**For Executives**:
- Business risk and impact
- Resource requirements
- Timeline and costs
- Strategic recommendations

**For Engineers**:
- Technical details
- Code snippets
- Step-by-step fixes
- Testing procedures

**For Compliance**:
- Control mappings
- Evidence trails
- Gap analysis
- Audit documentation

## Example Report Generation

### Complete Review Report Generation

```bash
# 1. Run complete security review
/grimbard-review /path/to/project

# 2. Reports are automatically generated in:
#    ./security-review-output/reports/
#    - executive-summary.md
#    - technical-findings.md
#    - report.html

# 3. Review and customize as needed
```

### Compliance Audit Report Generation

```bash
# 1. Run compliance audit
/grimbard-compliance /path/to/project

# 2. Additional compliance reports generated:
#    ./compliance-audit/
#    - COMPLIANCE_REPORT.md
#    - compliance-matrix.md
#    - gap-analysis.md

# 3. Use compliance-matrix template for final report
```

## Template Formats

### Markdown Templates (Default)

Most flexible, human-readable, version-control friendly:

```markdown
# {{PROJECT_NAME}} Security Report

**Scan Date**: {{SCAN_DATE}}

## Summary

Total Findings: {{TOTAL_FINDINGS}}
- Critical: {{P0_COUNT}}
- High: {{P1_COUNT}}
```

### HTML Templates

For interactive web reports:

```html
<!DOCTYPE html>
<html>
<head>
  <title>{{PROJECT_NAME}} Security Report</title>
</head>
<body>
  <h1>Security Assessment Report</h1>
  <p>Date: {{SCAN_DATE}}</p>
  <!-- ... -->
</body>
</html>
```

### JSON Templates

For programmatic processing:

```json
{
  "project": "{{PROJECT_NAME}}",
  "scanDate": "{{SCAN_DATE}}",
  "findings": {
    "critical": {{P0_COUNT}},
    "high": {{P1_COUNT}}
  }
}
```

## Custom Template Development

### Creating a New Template

1. **Identify Audience**: Who will read this report?

2. **Define Purpose**: What decisions should this report enable?

3. **Choose Structure**: Executive, technical, or compliance format?

4. **Add Sections**:
   - Summary/Overview
   - Key Findings
   - Details
   - Recommendations
   - Appendices

5. **Insert Variables**: Use `{{VAR_NAME}}` for dynamic content

6. **Test**: Generate report with sample data

### Template Testing

```bash
# Create test data
cat > test-data.json << EOF
{
  "PROJECT_NAME": "Test Project",
  "SCAN_DATE": "2026-01-22",
  "TOTAL_FINDINGS": 42,
  "P0_COUNT": 3
}
EOF

# Apply template with test data
# Use templating tool (jinja2, mustache, etc.)
```

## Integration with External Tools

### Jira

Export findings as Jira-compatible CSV:

```bash
# Use finding-template.md to generate Jira import format
python generate_jira_csv.py \
  --sarif ./security-review-output/sarif/consolidated.sarif \
  --template ./templates/finding-template.md \
  --output jira-import.csv
```

### Slack

Post summary to Slack:

```bash
# Use executive-summary.md to create Slack message
python post_to_slack.py \
  --report ./security-review-output/reports/executive-summary.md \
  --webhook $SLACK_WEBHOOK_URL
```

### Confluence

Upload report to Confluence:

```bash
# Convert markdown to Confluence storage format
pandoc executive-summary.md \
  -t confluence \
  -o confluence-report.xml

# Upload to Confluence API
```

## Accessibility

Reports should be accessible:

- ✓ Use semantic heading hierarchy (H1 → H2 → H3)
- ✓ Include alt text for images
- ✓ Use tables for tabular data
- ✓ Ensure sufficient color contrast
- ✓ Provide text descriptions for severity indicators

## Internationalization

For multi-language support:

```bash
templates/
├── en/
│   ├── executive-summary.md
│   ├── technical-findings.md
│   └── compliance-matrix.md
├── es/
│   └── [Spanish templates]
└── fr/
    └── [French templates]
```

## Version Control

Track template changes:

```bash
# Template changelog
templates/CHANGELOG.md

# Version templates
templates/v1.0/
templates/v2.0/
```

## Support

For template questions:
- **GitHub Issues**: https://github.com/igbuend/grimbard/issues
- **Discussions**: https://github.com/igbuend/grimbard/discussions
- **Examples**: See `examples/` directory for sample reports
