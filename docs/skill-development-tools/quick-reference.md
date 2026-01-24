# Skill Development Tools - Quick Reference

Quick reference guide for skill development and validation tools in the grimbard repository.

## Available Tools

### Skill Best Practices Reviewer

**Purpose:** Validate skills against Claude Code best practices

**Usage:**
```
/skill-best-practices-reviewer path/to/SKILL.md
```

**What it checks:**
- ✅ Metadata and frontmatter
- ✅ Content structure
- ✅ Workflow design
- ✅ Knowledge organization
- ✅ Tool usage patterns
- ✅ Verification steps
- ✅ Code examples
- ✅ Anti-patterns
- ✅ Language/tone
- ✅ Maintainability

**Output:**
- Summary and strengths
- Critical issues, recommendations, suggestions
- Context efficiency score (1-5)
- Overall assessment
- Specific improvements with diffs

## Quick Validation Checklist

Before publishing a skill, verify:

- [ ] Has clear `name` and `description` in frontmatter
- [ ] Uses `disable-model-invocation: true` if it's a workflow with side effects
- [ ] Description explains WHEN to use the skill
- [ ] Content is concise (no unnecessary prose)
- [ ] Includes verification steps for workflows
- [ ] Has code examples (BAD/GOOD patterns) where applicable
- [ ] No generic advice Claude already knows
- [ ] Not duplicating CLAUDE.md content
- [ ] Focused scope (not kitchen-sink)
- [ ] Links to external docs rather than duplicating them

## Context Efficiency Guidelines

**Target Scores:**
- **5/5** - Production ready, exemplary
- **4/5** - Good, minor improvements
- **3/5** - Acceptable, needs some work
- **2/5** - Needs significant revision
- **1/5** - Major rework required

**How to improve:**
1. Remove generic advice
2. Use bullet points, not paragraphs
3. Cut redundant explanations
4. Link to docs instead of duplicating
5. Break into focused skills if >500 lines

## Common Anti-Patterns

| Anti-Pattern | Fix |
|--------------|-----|
| **Encyclopedia Skill** | Break into focused skills or link to external docs |
| **CLAUDE.md Duplicate** | Move project rules to CLAUDE.md |
| **Vague Guide** | Provide specific, actionable patterns |
| **Context Hog** | Compress, split, or make invokable-only |
| **Rigid Workflow** | Provide guidance, not rigid sequences |
| **Missing Verification** | Add verification steps and success criteria |
| **Assumption Maker** | Be explicit about paths and locations |

## Skill Types

### Workflow Skill (Invokable)

```markdown
---
name: my-workflow
description: What it does and when to use it
disable-model-invocation: true
---

# My Workflow

Do something with $ARGUMENTS.

## Steps

1. **Step one**
   - Specific action
   - Command to run

2. **Verify**
   - Check success
   - Run tests
```

### Knowledge Skill (Auto-Applied)

```markdown
---
name: my-conventions
description: Project conventions for X
---

# My Conventions

## Pattern A
- Rule 1
- Rule 2
- Example: `code here`

## Pattern B
- Rule 1
- Rule 2
```

## Best Practices Summary

### DO
- ✅ Provide patterns Claude can't infer
- ✅ Include verification steps
- ✅ Use bullet points for scannability
- ✅ Add code examples with language tags
- ✅ Link to authoritative sources
- ✅ Be specific about file paths
- ✅ Specify exact commands to run

### DON'T
- ❌ Include generic advice
- ❌ Duplicate CLAUDE.md content
- ❌ Write encyclopedic skills
- ❌ Assume context without specifying
- ❌ Skip verification steps
- ❌ Use vague language
- ❌ Over-engineer workflows

## Testing Your Skill

### 1. Dry Run

```
Use /my-skill to [do the thing] in a test environment
```

### 2. Review

```
/skill-best-practices-reviewer .claude/skills/my-skill/SKILL.md
```

### 3. Iterate

Address critical issues, implement recommendations, consider suggestions.

### 4. Production Test

```
Use /my-skill for a real task and observe results
```

## Integration Patterns

### Pre-commit Hook

```yaml
- repo: local
  hooks:
    - id: skill-review
      name: Review skills
      entry: claude -p "Review SKILL.md using /skill-best-practices-reviewer"
      language: system
      files: 'SKILL\.md$'
```

### CI/CD

```yaml
- name: Validate Skills
  run: |
    claude -p "Review all SKILL.md files and fail if critical issues found"
```

### Make Target

```makefile
review-skills:
	@claude -p "Review all skills in .claude/skills/ using /skill-best-practices-reviewer"
```

## Resources

- [Full Documentation](./skill-best-practices-reviewer.md)
- [Claude Code Best Practices](https://code.claude.com/docs/en/best-practices)
- [Skills Guide](https://code.claude.com/docs/en/skills)
- [grimbard Repository](https://github.com/igbuend/grimbard)

## Support

- **Issues**: https://github.com/igbuend/grimbard/issues
- **Discussions**: https://github.com/igbuend/grimbard/discussions
- **Support**: https://ko-fi.com/igbuend
