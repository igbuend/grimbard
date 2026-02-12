# Skill Best Practices Reviewer

A skill for reviewing Claude Code skills against official best practices and recommendations.

## Purpose

This skill helps you create high-quality, context-efficient skills by validating them against the official Claude Code best practices. It performs comprehensive audits of skill files to ensure they:

- Follow recommended structure and formatting
- Are context-efficient and concise
- Include appropriate verification steps
- Have clear metadata and descriptions
- Avoid common anti-patterns
- Provide actionable, specific guidance

## When to Use

Use this skill when:
- Creating new skills for validation before publication
- Reviewing existing skills for improvement opportunities
- Debugging why a skill isn't working as expected
- Ensuring skills meet quality standards before sharing
- Auditing a repository of skills for consistency

## Installation

```bash
npx skills add igbuend/grimbard/skills/skill-reviewer
```

Or install the entire grimbard repository:

```bash
npx skills add igbuend/grimbard
```

## Usage

### Review a specific skill

```
/skill-reviewer .claude/skills/my-skill/SKILL.md
```

### Review all skills in a directory

```
Review all skill files in .claude/skills/ using the skill-reviewer
```

### Quick validation

```
Use /skill-reviewer to validate this skill draft:
[paste skill content]
```

## What It Checks

The reviewer validates skills against 10 key criteria:

1. **Skill Metadata** - Proper frontmatter, clear descriptions
2. **Content Structure** - Organization, formatting, scannability
3. **Workflow Skills** - Numbered steps, verification, parameters
4. **Knowledge Skills** - Domain knowledge, patterns, conventions
5. **Tool Usage** - Recommends appropriate tools, context-efficient patterns
6. **Verification** - Self-checking steps, success criteria
7. **Code Examples** - Syntax, completeness, BAD/GOOD patterns
8. **Anti-Patterns** - Avoids common mistakes
9. **Language & Tone** - Clear, concise, professional
10. **Maintenance** - Sustainability, version-agnostic

## Output Format

The skill provides structured feedback:

- **Summary** - Brief overview of quality
- **Strengths** - What works well
- **Issues Found** - Critical/Recommendations/Suggestions
- **Context Efficiency Score** - 1-5 rating
- **Overall Assessment** - Pass/Pass with Recommendations/Needs Revision
- **Specific Improvements** - Diffs showing suggested changes

## Common Issues Detected

### Critical Issues (Must Fix)
- Missing required frontmatter fields
- No verification or validation steps
- Overly broad scope (kitchen-sink skills)
- Duplicate content from CLAUDE.md
- Missing `disable-model-invocation` for side-effect workflows

### Recommendations (Should Fix)
- Verbose or redundant content
- Generic advice Claude already knows
- Missing code examples for patterns
- Unclear "when to use" guidance
- Poor organization or structure

### Suggestions (Nice to Have)
- Additional examples
- Better formatting
- External documentation links
- Improved naming or descriptions

## Example Review Output

```markdown
## Skill Review: api-conventions

### Summary
Focused knowledge skill providing REST API design conventions. Well-structured and context-efficient.

### Strengths
- Concise bullet-point format
- Scannable sections
- Provides patterns Claude can't infer from code
- Context-efficient (no unnecessary prose)

### Issues Found

#### Recommendations (Should Fix)
- [ ] Add example of RFC 7807 Problem Details format - Location: Error Handling section

#### Suggestions (Nice to Have)
- [ ] Consider adding authentication/authorization conventions

### Context Efficiency Score
5/5 - Extremely concise, every word necessary

### Overall Assessment
Pass with Recommendations
```

## Based On

This skill is based on the official Claude Code best practices:
- [Best Practices](https://code.claude.com/docs/en/best-practices)
- [Skills Guide](https://code.claude.com/docs/en/skills)
- [How Claude Code Works](https://code.claude.com/docs/en/how-claude-code-works)

## Related Skills

- **skill-developer** - Create new skills from scratch
- **skill-optimizer** - Optimize existing skills for performance
- **claude-md-reviewer** - Review CLAUDE.md files for quality

## License

MIT License - See main repository for details

## Contributing

Found an issue or have a suggestion? Please open an issue at:
https://github.com/igbuend/grimbard/issues

## Author

**igbuend**
- GitHub: https://github.com/igbuend
- Support: https://ko-fi.com/igbuend
