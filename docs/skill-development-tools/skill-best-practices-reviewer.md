# Skill Best Practices Reviewer

**Status:** Production Ready
**Version:** 1.0.0
**Category:** Skill Development Tools
**Author:** igbuend

## Overview

The Skill Best Practices Reviewer is a comprehensive auditing tool for Claude Code skills. It validates skill files against official best practices from the Claude Code documentation to ensure skills are well-designed, context-efficient, and effective.

## Purpose

Creating high-quality skills requires understanding Claude Code's architecture, context constraints, and recommended patterns. This reviewer automates the validation process, catching common mistakes and suggesting improvements based on official guidelines.

## Features

### Comprehensive Validation

Reviews skills across 10 key dimensions:
- Skill metadata and frontmatter
- Content structure and organization
- Workflow design (for invokable skills)
- Knowledge structure (for auto-applied skills)
- Tool usage recommendations
- Verification and validation steps
- Code examples and formatting
- Anti-pattern detection
- Language and tone
- Long-term maintainability

### Structured Feedback

Provides actionable feedback in a consistent format:
- **Summary** - Quick overview of the skill's quality
- **Strengths** - What the skill does well
- **Issues** - Categorized as Critical/Recommendations/Suggestions
- **Context Efficiency Score** - 1-5 rating with explanation
- **Overall Assessment** - Pass/Pass with Recommendations/Needs Revision
- **Specific Improvements** - Diffs showing suggested changes

### Context-Aware Analysis

Recognizes different skill types and applies appropriate criteria:
- **Workflow skills** - Validates step structure, verification, parameters
- **Knowledge skills** - Checks for domain-specific guidance vs. generic advice
- **Hybrid skills** - Validates both aspects appropriately

## Installation

### Install from grimbard repository

```bash
npx add-skill igbuend/grimbard
```

### Install standalone

```bash
npx add-skill igbuend/grimbard/skills/skill-best-practices-reviewer
```

## Usage

### Review a specific skill

```
/skill-best-practices-reviewer .claude/skills/my-skill/SKILL.md
```

### Review all skills in your project

```
Review all SKILL.md files in .claude/skills/ using /skill-best-practices-reviewer
```

### Validate a skill draft

```
Use /skill-best-practices-reviewer to check this skill:

---
name: my-skill
description: Does something useful
---

[paste skill content here]
```

### Get recommendations before publishing

```
Use /skill-best-practices-reviewer to audit all skills in the skills/ directory before I publish this repository
```

## Validation Criteria

### 1. Skill Metadata

**What it checks:**
- Required frontmatter fields (`name`, `description`)
- Appropriate use of `disable-model-invocation` flag
- Clear, concise description explaining WHEN to use the skill
- Kebab-case naming convention

**Common issues:**
- Missing or vague descriptions
- Wrong invocation mode for workflow skills
- Names that are too generic or too specific

### 2. Content Structure

**What it checks:**
- Clear section headers
- Consistent markdown formatting
- Scannable bullet points and lists
- Appropriate use of code blocks
- Links to external documentation

**Common issues:**
- Wall-of-text prose
- Inconsistent formatting
- Missing examples
- No clear organization

### 3. Workflow Skills

**What it checks:**
- Numbered steps with clear progression
- Use of `$ARGUMENTS` variable
- Verification/validation steps
- Success criteria
- Error handling guidance

**Common issues:**
- Missing verification steps
- Vague or unclear steps
- No error handling
- Assumes context without specifying files/locations

### 4. Knowledge Skills

**What it checks:**
- Provides patterns Claude can't infer from code
- Domain-specific guidance vs. generic advice
- Code examples with BAD/GOOD patterns
- Focused scope (not kitchen-sink)

**Common issues:**
- Generic advice Claude already knows
- Too broad (tries to cover entire domain)
- Duplicates CLAUDE.md content
- No actionable examples

### 5. Tool Usage

**What it checks:**
- Recommends appropriate tools (Read vs Bash cat, Grep vs Bash grep)
- Suggests parallel tool calls when applicable
- Uses subagents for context-heavy tasks
- Avoids unnecessary tool use

**Common issues:**
- Recommends inefficient tool usage
- Doesn't scope searches or reads
- Missing subagent recommendations
- Clutters context with unnecessary exploration

### 6. Verification & Validation

**What it checks:**
- Steps for Claude to verify its work
- Clear success criteria
- Test commands or validation scripts
- Addresses root causes, not symptoms

**Common issues:**
- "Implement X" without "test X"
- No way to verify correctness
- Missing test commands
- Symptom-focused fixes

### 7. Code Examples

**What it checks:**
- Proper syntax highlighting
- Complete, runnable examples
- BAD/GOOD pattern comparisons
- Realistic, practical examples
- Explanatory comments

**Common issues:**
- Missing language tags
- Pseudocode fragments
- No BAD/GOOD comparison
- Toy examples instead of realistic ones

### 8. Anti-Patterns

**What it checks:**
- Avoids being too long (>500 lines)
- Not too vague or generic
- Not too rigid or prescriptive
- Doesn't duplicate CLAUDE.md
- Doesn't over-engineer

**Common issues:**
- Encyclopedia skills (too comprehensive)
- CLAUDE.md duplicates
- Vague guides with no specifics
- Context hogs (1000+ lines auto-loaded)
- Rigid workflows with no flexibility

### 9. Language & Tone

**What it checks:**
- Imperative voice for instructions
- Concise and direct
- Professional and objective
- No unnecessary adjectives
- No emojis (unless domain-appropriate)

**Common issues:**
- Verbose prose
- Passive voice
- Marketing-style language
- Unnecessary superlatives

### 10. Maintenance

**What it checks:**
- Version-agnostic content
- Links to official docs for evolving references
- Dates/context for time-sensitive info
- Incrementally updatable

**Common issues:**
- Hardcoded version numbers
- Duplicated documentation that will become stale
- No dates on time-sensitive content

## Context Efficiency Scoring

The reviewer provides a 1-5 context efficiency score:

- **5 - Extremely concise** - Every word is necessary, no verbosity
- **4 - Mostly efficient** - Minor areas could be tightened
- **3 - Acceptable** - Some verbosity, but generally good
- **2 - Verbose** - Significant trimming needed
- **1 - Bloated** - Major revision required

This score reflects one of Claude Code's core constraints: **context window fills fast, and performance degrades as it fills**. Skills should be maximally concise while remaining clear.

## Issue Severity Levels

### Critical Issues (Must Fix)
Issues that will cause the skill to malfunction or violate core principles:
- Missing required frontmatter
- Incorrect invocation mode
- No verification steps in workflows
- Overly broad scope
- Duplicates CLAUDE.md

### Recommendations (Should Fix)
Issues that reduce effectiveness but don't prevent functionality:
- Verbose content
- Generic advice
- Missing examples
- Unclear structure
- Poor organization

### Suggestions (Nice to Have)
Improvements that would enhance quality:
- Additional examples
- Better formatting
- External links
- Improved naming

## Common Skill Smells

### The Encyclopedia Skill
**Symptom:** Tries to cover an entire domain exhaustively
**Impact:** Context bloat, information overload
**Fix:** Break into focused skills or link to external docs

### The CLAUDE.md Duplicate
**Symptom:** Contains project-specific conventions
**Impact:** Confusion about where rules live, duplication
**Fix:** Move project rules to CLAUDE.md, keep domain knowledge in skills

### The Vague Guide
**Symptom:** Generic advice like "write clean code"
**Impact:** No value-add, Claude already knows this
**Fix:** Provide specific, actionable patterns

### The Context Hog
**Symptom:** Auto-loaded skill with 1000+ lines
**Impact:** Fills context window, degrades performance
**Fix:** Compress, split, or make invokable-only

### The Rigid Workflow
**Symptom:** Overly prescriptive steps, no flexibility
**Impact:** Can't adapt to variations or edge cases
**Fix:** Provide guidance and checkpoints, not rigid sequences

### The Missing Verification
**Symptom:** Implementation without validation
**Impact:** Can't verify correctness, ships bugs
**Fix:** Add verification steps, success criteria, tests

### The Assumption Maker
**Symptom:** "Update the config" without saying which file
**Impact:** Claude has to guess, often gets it wrong
**Fix:** Be explicit about paths, patterns, discovery methods

## Example Review

### Input: API Conventions Skill

```markdown
---
name: api-conventions
description: REST API design conventions for our microservices
---

# API Conventions

## URL Structure
- Use kebab-case: `/api/v1/user-profiles`
- Version in path: `/v1/`, `/v2/`
- Collection naming: plural (`/users`, not `/user`)

## Request/Response Format
- Use camelCase for JSON properties
- ISO 8601 for timestamps: `2024-01-15T10:30:00Z`
- Wrap list responses: `{ "data": [...], "meta": { "total": 100 } }`

## Pagination
- Cursor-based for large datasets
- Include `next`, `prev` in meta
- Limit: max 100 items per page
```

### Output: Review Results

```markdown
## Skill Review: api-conventions

### Summary
Focused knowledge skill providing REST API design conventions. Well-structured and context-efficient.

### Strengths
- Concise bullet-point format makes it scannable
- Provides patterns Claude can't infer from code alone
- Context-efficient with no unnecessary prose
- Clear sections organized by topic
- Specific examples (kebab-case, camelCase, ISO 8601)

### Issues Found

#### Recommendations (Should Fix)
- [ ] Add example of complete error response format - Location: Request/Response Format section
- [ ] Consider adding authentication/authorization header conventions

#### Suggestions (Nice to Have)
- [ ] Link to RFC 7807 for error format reference
- [ ] Add example of pagination response structure

### Context Efficiency Score
5/5 - Extremely concise, every word necessary

### Overall Assessment
Pass with Recommendations

### Specific Improvements

Consider adding to the Request/Response Format section:

```diff
## Request/Response Format
- Use camelCase for JSON properties
- ISO 8601 for timestamps: `2024-01-15T10:30:00Z`
- Wrap list responses: `{ "data": [...], "meta": { "total": 100 } }`
+ Error format (RFC 7807): `{ "type": "...", "title": "...", "status": 400, "detail": "..." }`
```
```

## Best Practices for Using This Reviewer

### During Development

Run the reviewer frequently while developing skills:

```
/skill-best-practices-reviewer .claude/skills/my-new-skill/SKILL.md
```

This catches issues early when they're easier to fix.

### Before Publication

Always review before publishing or sharing:

```
Review all skills in this repository using /skill-best-practices-reviewer before I publish to GitHub
```

This ensures consistent quality across your skill collection.

### For Continuous Improvement

Periodically audit existing skills:

```
Use /skill-best-practices-reviewer to audit the top 10 most-used skills in .claude/skills/ and suggest improvements
```

Skills evolve, and periodic reviews catch staleness.

### For Team Standards

Use as a quality gate in your team's workflow:

```
Review the skill in this PR using /skill-best-practices-reviewer
```

This maintains consistent quality across team contributions.

## Integration with Other Tools

### Pre-commit Hooks

Add to `.pre-commit-config.yaml`:

```yaml
- repo: local
  hooks:
    - id: skill-review
      name: Review skills for best practices
      entry: claude -p "Review changed SKILL.md files using /skill-best-practices-reviewer"
      language: system
      files: 'SKILL\.md$'
```

### CI/CD Pipeline

Add to GitHub Actions:

```yaml
- name: Review Skills
  run: |
    claude -p "Review all SKILL.md files using /skill-best-practices-reviewer and fail if any critical issues found"
```

### IDE Integration

Configure as a task in VS Code (`.vscode/tasks.json`):

```json
{
  "label": "Review Skill",
  "type": "shell",
  "command": "claude -p '/skill-best-practices-reviewer ${file}'"
}
```

## Limitations

### What This Reviewer Does NOT Check

- **Correctness** - It doesn't validate that code examples actually work
- **Completeness** - It doesn't verify domain knowledge is accurate
- **Usefulness** - It can't assess if the skill solves a real problem
- **Performance** - It doesn't measure actual runtime performance
- **Security** - It's not a security auditing tool

### Manual Review Still Required

This reviewer validates structure and adherence to best practices, but human judgment is still needed for:
- Domain accuracy
- Skill necessity
- User experience
- Edge case coverage
- Integration with other skills

## References

Based on official Claude Code documentation:
- [Best Practices](https://code.claude.com/docs/en/best-practices)
- [Skills Guide](https://code.claude.com/docs/en/skills)
- [How Claude Code Works](https://code.claude.com/docs/en/how-claude-code-works)
- [Context Management](https://code.claude.com/docs/en/costs#reduce-token-usage)

## Contributing

Found issues or have suggestions? Please contribute:

1. **Report bugs** - https://github.com/igbuend/grimbard/issues
2. **Suggest improvements** - Submit a PR with proposed changes
3. **Share examples** - Add your skill review examples to the docs

## License

MIT License - See repository root for details

## Related Skills

- **skill-developer** - Create new skills from templates
- **skill-optimizer** - Optimize skills for performance
- **claude-md-reviewer** - Review CLAUDE.md files
- **hook-validator** - Validate hook configurations

## Changelog

### v1.0.0 (2026-01-24)
- Initial release
- Comprehensive validation across 10 dimensions
- Structured feedback format
- Context efficiency scoring
- Common anti-pattern detection
- Example reviews and best practices

## Support

- **Documentation**: https://github.com/igbuend/grimbard/docs
- **Issues**: https://github.com/igbuend/grimbard/issues
- **Discussions**: https://github.com/igbuend/grimbard/discussions
- **Support**: https://ko-fi.com/igbuend
