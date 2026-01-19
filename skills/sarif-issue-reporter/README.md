# SARIF Issue Reporter (SIR)

A comprehensive Claude skill for analyzing SARIF security scan results and generating detailed vulnerability reports with CVSS scoring, exploitation scenarios, compliance mapping, and remediation guidance.

## 📋 Overview

The SARIF Issue Reporter skill transforms raw SARIF files from security scanning tools into actionable security reports that include:

- ✅ **Verification** - Confirms findings are true positives, not false alarms
- 📊 **CVSS 3.1 Scoring** - Calculates standardized vulnerability scores
- 💥 **Exploitation Scenarios** - Demonstrates real-world attack vectors
- 🛡️ **Security Pattern Analysis** - Identifies violated security patterns
- 📚 **Standards Mapping** - Links to OWASP, CWE, CAPEC, compliance frameworks
- 🔧 **Remediation Code** - Provides working fixes, not just advice
- 📖 **References** - Connects to authoritative security resources

## 🗂️ Package Contents

```
sarif-issue-reporter/
├── SKILL.md              # Main skill documentation for Claude
├── sarif_helper.py       # Python utility for SARIF parsing
├── example.sarif         # Sample SARIF file for testing
├── USAGE_GUIDE.md        # Comprehensive usage instructions
└── README.md            # This file
```

## 🚀 Quick Start

### 1. Install Dependencies

```bash
# No external dependencies required for basic usage
# Python 3.7+ with standard library
```

### 2. Test with Example

```bash
# Parse the example SARIF file
python sarif_helper.py example.sarif --output test_report.md

# Review the generated template
cat test_report.md
```

### 3. Use with Claude

Upload `example.sarif` to Claude and say:

> "Using the sarif-issue-reporter skill, analyze this SARIF file and generate a comprehensive security report for all critical issues."

## 📖 Documentation

### Main Skill Documentation

**File**: `SKILL.md`

This is the primary skill file that Claude reads to understand how to:
- Parse SARIF files
- Verify security findings
- Calculate CVSS scores
- Map to security standards
- Generate comprehensive reports

### Usage Guide

**File**: `USAGE_GUIDE.md`

Detailed instructions including:
- Step-by-step workflows
- Example prompts
- Advanced usage patterns
- Integration strategies
- Troubleshooting tips

### Helper Script

**File**: `sarif_helper.py`

Python utility for:
- Parsing SARIF files
- Extracting issue details
- Generating report templates
- Statistics and filtering

## 🎯 Use Cases

### Security Code Review
```bash
# Scan your codebase
semgrep --config=auto --sarif > results.sarif

# Generate report template
python sarif_helper.py results.sarif --severity error --output report.md

# Use Claude for detailed analysis
# Upload results.sarif and relevant source files to Claude
```

### Compliance Audit
```
"Analyze this SARIF file and map all findings to PCI-DSS requirements.
For each critical issue, provide evidence for compliance reporting."
```

### Vulnerability Disclosure
```
"Generate a detailed vulnerability report for ISSUE-003 suitable for
responsible disclosure, including CVSS score, POC, and remediation."
```

### Security Training
```
"Using these SARIF results, create training materials that explain each
vulnerability type, how to exploit it, and how to prevent it."
```

## 🔄 Workflow Integration

### CI/CD Pipeline

```yaml
# Example GitHub Actions workflow
name: Security Analysis

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Run Security Scan
        run: semgrep --config=auto --sarif > results.sarif

      - name: Generate Report Template
        run: python sarif_helper.py results.sarif --output report.md

      - name: Upload Artifacts
        uses: actions/upload-artifact@v2
        with:
          name: security-reports
          path: |
            results.sarif
            report.md
```

### Manual Review Process

1. **Scan**: Run your security scanner (Semgrep, SonarQube, CodeQL, etc.)
2. **Parse**: Use `sarif_helper.py` to extract and organize findings
3. **Analyze**: Upload to Claude for detailed verification and analysis
4. **Report**: Generate comprehensive security reports
5. **Remediate**: Implement suggested fixes
6. **Verify**: Re-scan to confirm issues are resolved

## 🔍 Example Analysis

Given this vulnerable code in a SARIF file:

```javascript
const query = `SELECT * FROM users WHERE id = '${userId}'`;
```

The skill generates:

```markdown
## [ISSUE-001] SQL Injection Vulnerability

**Severity**: CRITICAL
**CVSS 3.1 Score**: 10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)

### Exploitation Scenario
An attacker can inject SQL code via the userId parameter to bypass
authentication, extract sensitive data, or modify database contents.

**Proof of Concept**:
```http
GET /api/users/1' OR '1'='1 HTTP/1.1
```

### Security Patterns Violated
- **Input Validation Pattern**: No validation performed on userId
- **Output Encoding Pattern**: Using string concatenation instead of parameterized queries

### Standards Mapping
- **OWASP Top 10**: A03:2021 – Injection
- **CWE**: CWE-89 (SQL Injection)
- **CAPEC**: CAPEC-66 (SQL Injection)
- **PCI-DSS**: Requirement 6.5.1

### Remediation
```javascript
// Use parameterized queries
const query = 'SELECT * FROM users WHERE id = ?';
const results = await db.query(query, [userId]);
```
```

## 🛠️ Helper Script Usage

### Basic Commands

```bash
# View statistics
python sarif_helper.py results.sarif --stats-only

# Filter by severity
python sarif_helper.py results.sarif --severity error

# Generate report template
python sarif_helper.py results.sarif --output report.md

# Analyze specific run
python sarif_helper.py results.sarif --run 0
```

### Output Examples

```
SARIF Version: 2.1.0
Number of runs: 1

Tool: SecurityScanner v2.5.0

Severity Distribution:
  Critical/Error: 3
  Warning: 1
  Note/Info: 0

Files with issues: 4

Issues to report (filtered by severity: error): 3
```

## 🔗 Integration with Security Patterns

This skill automatically references your security patterns repository:

```
D:\github\patterns\skills\
├── cryptographic-key-management/
├── data-validation/
├── output-filter/
├── cryptography-as-a-service/
└── self-managed-cryptography/
```

When analyzing issues, Claude will:
- Identify which patterns were violated
- Reference pattern documentation
- Suggest pattern-based remediation
- Link to your local pattern files

## 📊 Supported SARIF Sources

The skill works with SARIF output from:

- **Semgrep** - Multi-language static analysis
- **CodeQL** - GitHub's code analysis platform
- **SonarQube** - Continuous code quality inspection
- **Snyk** - Security vulnerability scanner
- **Checkmarx** - Enterprise security testing
- **Fortify** - Static application security testing
- **ESLint** - JavaScript linter (with SARIF formatter)
- **Bandit** - Python security scanner
- **SpotBugs** - Java static analysis
- Any tool supporting SARIF 2.1.0 format

## 🎓 Best Practices

### 1. Verify Before Reporting
Always let Claude verify findings - SAST tools can produce false positives.

### 2. Provide Context
Upload relevant source files so Claude can analyze issues in context.

### 3. Customize for Your Needs
Specify compliance frameworks, pattern repositories, or output formats.

### 4. Iterate and Refine
Use Claude's findings to ask follow-up questions and deepen analysis.

### 5. Track Remediation
Export reports to your issue tracking system and monitor progress.

## 🔒 Security Considerations

- **Sensitive Data**: SARIF files may contain source code snippets - handle appropriately
- **Credentials**: Never commit SARIF files containing hardcoded secrets
- **False Positives**: Always verify findings before taking action
- **Remediation Testing**: Test all fixes before deploying to production

## 📝 Customization

### Adding Custom Standards

Modify `SKILL.md` to include your organization's standards:

```markdown
**Company Standards**:
- Internal Security Policy Section 5.2
- Architecture Review Board Requirement ARC-042
- Secure Coding Guidelines v3.1
```

### Custom Report Format

Request specific formats from Claude:

```
"Generate this report in HTML format with embedded CSS, suitable for
executive presentation, with a dashboard showing severity distribution."
```

### Integration with Custom Tools

Extend `sarif_helper.py` to integrate with your tools:

```python
# Example: Send to Jira
def create_jira_tickets(issues):
    for issue in issues:
        # Create ticket using Jira API
        pass
```

## 🤝 Contributing

Suggestions for improvement:

1. Additional compliance framework mappings
2. Support for more SARIF extensions
3. Integration with specific tools
4. Custom report templates
5. Automation scripts

## 📄 License

This skill is provided as-is for security analysis purposes.

## 🆘 Support

### Common Questions

**Q: What if my SARIF file doesn't include code snippets?**
A: Claude will request the relevant source files for context.

**Q: Can I analyze multiple SARIF files at once?**
A: Yes, combine them or analyze sequentially.

**Q: How accurate are the CVSS scores?**
A: Claude calculates scores based on the code context and provides full justification.

**Q: Can I customize the compliance mappings?**
A: Yes, specify your required frameworks in the prompt.

### Getting Help

Upload your SARIF file to Claude and ask:

> "I need help analyzing this SARIF file using the sarif-issue-reporter skill.
> What information do you need from me to generate a complete report?"

## 🔮 Future Enhancements

Potential additions:
- [ ] SARIF 2.2 support
- [ ] Automated remediation with git patches
- [ ] Trend analysis across multiple scans
- [ ] Integration with security orchestration platforms
- [ ] Machine learning for false positive detection
- [ ] Custom rule creation from patterns

## 📚 Additional Resources

- [SARIF Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Database](https://cwe.mitre.org/)
- [CVSS Calculator](https://www.first.org/cvss/calculator/3.1)
- [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/)

---

**Version**: 1.0.0
**Created**: 2025-01-18
**Author**: Herman
**Skill Name**: sarif-issue-reporter

For detailed usage instructions, see `USAGE_GUIDE.md`
For the complete skill documentation, see `SKILL.md`
