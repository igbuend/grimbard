#!/usr/bin/env python3
"""
SARIF Issue Reporter Helper Script

This script helps parse SARIF files and extract information needed for
comprehensive security issue reporting as defined in the sarif-issue-reporter skill.

Usage:
    python sarif_helper.py <sarif_file> [--severity critical,high] [--output report.md]
"""

import json
import sys
import argparse
from pathlib import Path
from typing import List, Dict, Any, Optional


class SARIFParser:
    """Parse and extract information from SARIF files"""

    def __init__(self, sarif_path: str):
        self.sarif_path = Path(sarif_path)
        with open(self.sarif_path, 'r', encoding='utf-8') as f:
            self.sarif = json.load(f)

        self.version = self.sarif.get('version', 'unknown')
        self.runs = self.sarif.get('runs', [])

    def get_tool_info(self, run_index: int = 0) -> Dict[str, Any]:
        """Extract tool information from a specific run"""
        if not self.runs or run_index >= len(self.runs):
            return {}

        tool = self.runs[run_index].get('tool', {}).get('driver', {})
        return {
            'name': tool.get('name', 'Unknown'),
            'version': tool.get('version', 'Unknown'),
            'informationUri': tool.get('informationUri', ''),
            'rules': tool.get('rules', [])
        }

    def get_rule_info(self, rule_id: str, run_index: int = 0) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific rule"""
        tool_info = self.get_tool_info(run_index)
        rules = tool_info.get('rules', [])

        for rule in rules:
            if rule.get('id') == rule_id:
                return {
                    'id': rule.get('id'),
                    'name': rule.get('name', ''),
                    'shortDescription': rule.get('shortDescription', {}).get('text', ''),
                    'fullDescription': rule.get('fullDescription', {}).get('text', ''),
                    'help': rule.get('help', {}).get('text', ''),
                    'helpUri': rule.get('helpUri', ''),
                    'properties': rule.get('properties', {})
                }
        return None

    def get_results(self, run_index: int = 0, severity_filter: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Extract results (issues) from a specific run, optionally filtered by severity"""
        if not self.runs or run_index >= len(self.runs):
            return []

        results = self.runs[run_index].get('results', [])

        if severity_filter:
            severity_filter = [s.lower() for s in severity_filter]
            results = [r for r in results if r.get('level', 'warning').lower() in severity_filter]

        return results

    def get_issue_details(self, result: Dict[str, Any], run_index: int = 0) -> Dict[str, Any]:
        """Extract detailed information from a single result"""
        rule_id = result.get('ruleId', 'unknown')
        rule_info = self.get_rule_info(rule_id, run_index)

        # Extract location information
        locations = result.get('locations', [])
        primary_location = locations[0] if locations else {}
        physical_location = primary_location.get('physicalLocation', {})

        artifact_location = physical_location.get('artifactLocation', {})
        region = physical_location.get('region', {})

        # Extract code snippet
        snippet = region.get('snippet', {}).get('text', '')

        # Extract code flows for data flow analysis
        code_flows = result.get('codeFlows', [])

        # Build comprehensive issue details
        details = {
            'rule_id': rule_id,
            'rule_info': rule_info,
            'level': result.get('level', 'warning'),
            'message': result.get('message', {}).get('text', ''),
            'file': artifact_location.get('uri', 'unknown'),
            'start_line': region.get('startLine', 0),
            'end_line': region.get('endLine', region.get('startLine', 0)),
            'start_column': region.get('startColumn', 0),
            'end_column': region.get('endColumn', 0),
            'snippet': snippet,
            'code_flows': code_flows,
            'related_locations': result.get('relatedLocations', []),
            'properties': result.get('properties', {}),
            'rank': result.get('rank', 0),
            'fingerprints': result.get('fingerprints', {})
        }

        return details

    def get_severity_statistics(self, run_index: int = 0) -> Dict[str, int]:
        """Get count of issues by severity level"""
        results = self.get_results(run_index)
        stats = {'error': 0, 'warning': 0, 'note': 0, 'none': 0}

        for result in results:
            level = result.get('level', 'warning')
            stats[level] = stats.get(level, 0) + 1

        return stats

    def get_file_list(self, run_index: int = 0) -> List[str]:
        """Get list of all files with issues"""
        results = self.get_results(run_index)
        files = set()

        for result in results:
            locations = result.get('locations', [])
            for location in locations:
                physical_location = location.get('physicalLocation', {})
                artifact_location = physical_location.get('artifactLocation', {})
                uri = artifact_location.get('uri', '')
                if uri:
                    files.add(uri)

        return sorted(list(files))


def read_code_context(file_path: str, start_line: int, context_lines: int = 5) -> str:
    """Read code context around a specific line"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        start_idx = max(0, start_line - context_lines - 1)
        end_idx = min(len(lines), start_line + context_lines)

        context = []
        for i in range(start_idx, end_idx):
            line_num = i + 1
            marker = '>>> ' if line_num == start_line else '    '
            context.append(f"{marker}{line_num:4d} | {lines[i].rstrip()}")

        return '\n'.join(context)
    except Exception as e:
        return f"Error reading file: {e}"


def generate_issue_report_template(issue: Dict[str, Any], issue_number: int) -> str:
    """Generate a template report for a single issue following the skill format"""

    rule_info = issue.get('rule_info') or {}

    template = f"""
## [ISSUE-{issue_number:03d}] {rule_info.get('name', issue['rule_id'])}

**Severity**: {issue['level'].upper()}
**CVSS 3.1 Score**: [TO BE CALCULATED]
**Status**: Pending Verification

### Executive Summary
{issue['message']}

### Technical Description
{rule_info.get('fullDescription', 'No description available')}

### Code Evidence

**Location**: `{issue['file']}:{issue['start_line']}`

```
{issue['snippet'] or '[Code snippet not available in SARIF - needs extraction]'}
```

**Note**: Additional context needed for verification.

### Exploitation Scenario

**Attack Vector**: [TO BE DETERMINED]

**Proof of Concept**:
```
[TO BE DEVELOPED]
```

### Impact Assessment

**Confidentiality**: [TO BE ASSESSED]
**Integrity**: [TO BE ASSESSED]
**Availability**: [TO BE ASSESSED]

### Security Patterns Violated

[TO BE IDENTIFIED from security patterns repository]

### Standards & Compliance Mapping

**OWASP Top 10**: [TO BE MAPPED]
**CWE**: {rule_info.get('properties', {}).get('cwe', '[TO BE IDENTIFIED]')}
**CAPEC**: [TO BE MAPPED]

**OWASP Cheat Sheets**: [TO BE REFERENCED]

### Remediation Recommendations

**Priority**: [TO BE DETERMINED]

**Short-term Fix**:
```
[TO BE DEVELOPED]
```

**Long-term Solution**:
```
[TO BE DEVELOPED]
```

### References

- Rule Help: {rule_info.get('helpUri', 'N/A')}

---
"""
    return template


def main():
    parser = argparse.ArgumentParser(description='Parse SARIF files and extract security issues')
    parser.add_argument('sarif_file', help='Path to SARIF file')
    parser.add_argument('--severity', default='error,warning',
                       help='Comma-separated severity levels to include (error,warning,note)')
    parser.add_argument('--output', help='Output file for report template')
    parser.add_argument('--run', type=int, default=0, help='Run index to analyze (default: 0)')
    parser.add_argument('--stats-only', action='store_true', help='Only show statistics')

    args = parser.parse_args()

    # Parse SARIF file
    sarif = SARIFParser(args.sarif_file)

    print(f"SARIF Version: {sarif.version}")
    print(f"Number of runs: {len(sarif.runs)}")

    tool_info = sarif.get_tool_info(args.run)
    print(f"\nTool: {tool_info['name']} v{tool_info['version']}")

    # Statistics
    stats = sarif.get_severity_statistics(args.run)
    print(f"\nSeverity Distribution:")
    print(f"  Critical/Error: {stats.get('error', 0)}")
    print(f"  Warning: {stats.get('warning', 0)}")
    print(f"  Note/Info: {stats.get('note', 0)}")

    files = sarif.get_file_list(args.run)
    print(f"\nFiles with issues: {len(files)}")

    if args.stats_only:
        return

    # Get filtered results
    severity_list = args.severity.split(',')
    results = sarif.get_results(args.run, severity_list)

    print(f"\nIssues to report (filtered by severity: {args.severity}): {len(results)}")

    # Generate report templates
    report_parts = []
    report_parts.append(f"# Security Analysis Report\n")
    report_parts.append(f"**Scan Date**: [DATE]")
    report_parts.append(f"**Tool**: {tool_info['name']} v{tool_info['version']}")
    report_parts.append(f"**SARIF File**: {args.sarif_file}\n")
    report_parts.append(f"## Overview")
    report_parts.append(f"- **Total Issues Found**: {len(results)}")
    report_parts.append(f"- **Verified Issues**: [TO BE DETERMINED]")
    report_parts.append(f"- **False Positives**: [TO BE DETERMINED]\n")
    report_parts.append(f"## Detailed Findings\n")

    for idx, result in enumerate(results, 1):
        issue_details = sarif.get_issue_details(result, args.run)
        report_template = generate_issue_report_template(issue_details, idx)
        report_parts.append(report_template)

        print(f"\nIssue {idx}:")
        print(f"  Rule: {issue_details['rule_id']}")
        print(f"  File: {issue_details['file']}:{issue_details['start_line']}")
        print(f"  Severity: {issue_details['level']}")

    # Write output
    full_report = '\n'.join(report_parts)

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(full_report)
        print(f"\nReport template written to: {args.output}")
        print(f"Next step: Use Claude with sarif-issue-reporter skill to complete the analysis")
    else:
        print("\n" + "="*80)
        print(full_report)


if __name__ == '__main__':
    main()
