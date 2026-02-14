---
name: skill-reviewer
description: Reviews skills against Claude Code best practices. Use when auditing skill files for adherence to recommendations.
disable-model-invocation: true
aliases:
  - review-skill
---

# Skill Reviewer

Reviews skill files against Claude Code best practices.

**Target:** $ARGUMENTS (path to skill file or directory)

## When to Use

Use when:
- Creating new skills to validate best practices
- Reviewing existing skills for improvements
- Auditing before publication
- Debugging unexpected skill behavior
- Ensuring context efficiency

## Review Checklist

### Metadata

**Required frontmatter:**
- [ ] `name` (kebab-case, descriptive)
- [ ] `description` (when to use, not just what)
- [ ] `disable-model-invocation: true` for workflows with side effects
- [ ] `aliases` for common alternative names

**Quality:**
- Description: 1-2 sentences
- Name: specific yet broadly applicable

### Structure

**Organization:**
- [ ] Clear sections with descriptive headers
- [ ] Consistent markdown formatting
- [ ] Examples where applicable
- [ ] "When to Use" section for context

**Context efficiency:**
- [ ] Concise - only essential information
- [ ] No redundant explanations
- [ ] Bullet points for scannability
- [ ] Links to docs vs duplicating them
- [ ] No filler content

### Workflow Skills (Invokable)

For skills invoked with `/skill-name`:

- [ ] Uses `disable-model-invocation: true`
- [ ] Numbered steps or phases
- [ ] Actionable, specific steps
- [ ] Verification/validation steps
- [ ] Uses `$ARGUMENTS` if accepts parameters
- [ ] Logical step ordering
- [ ] Error handling or fallback guidance
- [ ] Clear when to ask user vs proceed autonomously
- [ ] Clear success criteria

### Knowledge Skills (Auto-Applied)

For skills Claude applies automatically:

- [ ] Domain knowledge Claude can't infer
- [ ] Patterns, conventions, architectural guidance
- [ ] Code examples with language tags
- [ ] Organized by topic/use case
- [ ] Focused scope (narrow > kitchen-sink)
- [ ] Not duplicating CLAUDE.md content
- [ ] Provides guidance, not rigid instructions

### Tool Usage

- [ ] Recommends right tool (Read vs bash cat)
- [ ] Suggests parallel calls when appropriate
- [ ] Uses subagents for context-heavy exploration
- [ ] Avoids unnecessary tool use

**Context-saving patterns:**
- [ ] Focused searches over broad exploration
- [ ] Filter/scope before reading large files
- [ ] Subagents for investigation
- [ ] Suggests `/clear` when context cluttered

### Verification

- [ ] Steps for Claude to verify work
- [ ] Defines success criteria
- [ ] Recommends tests, linters, validation
- [ ] Addresses root causes, not symptoms
- [ ] Prompts for confirmation on destructive actions
- [ ] Asks clarifying questions when ambiguous
- [ ] Progress updates for long tasks

### Code Examples

If included:

- [ ] Correct syntax highlighting
- [ ] Shows BAD and GOOD patterns when relevant
- [ ] Comments for non-obvious code
- [ ] Complete and runnable (not pseudocode)
- [ ] Realistic examples (not toy examples)

### Anti-Patterns to Avoid

**Content:**
- ❌ Too long (>500 lines)
- ❌ Too vague (generic advice)
- ❌ Too rigid (constrains creativity)
- ❌ Duplicates CLAUDE.md
- ❌ Over-engineered

**Workflow:**
- ❌ No verification steps
- ❌ Assumes context
- ❌ Unclear scope
- ❌ Missing error handling
- ❌ No user interaction on destructive actions

### Language & Tone

**Principles:**
- [ ] Imperative voice ("Run tests" not "You should run tests")
- [ ] Concise and direct
- [ ] Precise terminology
- [ ] Active voice preferred
- [ ] One idea per sentence
- [ ] No unnecessary adjectives/superlatives
- [ ] Professional, objective tone
- [ ] No emojis (unless domain-specific)

**Eliminate verbosity:**
- "In order to" → "To"
- "It is important to note that" → (delete)
- "You should" / "You need to" → imperative
- "Please note that" → (delete)
- "Going forward" / "Moving forward" → (delete)
- "At this point in time" → "Now" or (delete)
- "For the purpose of" → "To" or "For"
- "With regard to" → "About" or "Regarding"

### Maintenance

- [ ] Version-agnostic (no specific tool versions)
- [ ] Links to official docs for evolving refs
- [ ] Dates for time-sensitive information
- [ ] Can update incrementally

## Technical Writing Principles

### Precision Over Description

**BAD:** "Make sure your code is well-organized and follows good practices"  
**GOOD:** "Use dependency injection. Limit functions to 50 lines."

### Eliminate Filler

Common filler: "basically", "essentially", "generally", "typically", "very", "really", "quite", "actually", "kind of", "sort of", "simply", "just"

**BAD:** "You should basically just run the tests to make sure everything is actually working correctly"  
**GOOD:** "Run tests to verify functionality"

### Use Concrete Numbers

**BAD:** "Keep functions small and avoid deeply nested code"  
**GOOD:** "Limit functions to 50 lines. Limit nesting to 3 levels."

### Active Voice

**BAD:** "The configuration should be validated before the application is started"  
**GOOD:** "Validate configuration before starting the application"

### Front-Load Important Info

**BAD:** "When you're working with user input, which could potentially contain malicious data, it's important to remember that you should always validate and sanitize it"  
**GOOD:** "Always validate and sanitize user input"

### Parallel Structure

**BAD:**
- Check that the file exists
- Making sure permissions are correct
- You should verify the contents

**GOOD:**
- Check file exists
- Verify permissions
- Validate contents

### Delete Hedge Words

**BAD:** "This might help improve performance somewhat"  
**GOOD:** "This improves performance by 30%" or "This may improve performance. Benchmark to verify."

## Review Process

1. Read skill at $ARGUMENTS
2. Check frontmatter for required fields
3. Evaluate context efficiency
4. Apply technical writing check
5. Verify structure and flow
6. Test code examples
7. Check for anti-patterns
8. Assess scope
9. Validate verification steps

## Output Format

```markdown
## Skill Review: [skill-name]

### Summary
[1-2 sentence overview]

### Strengths
- [What works well]
- [Effective patterns]

### Issues Found

#### Critical (Must Fix)
- [ ] [Issue] - Location: [section/line]

#### Recommendations (Should Fix)
- [ ] [Recommendation] - Location: [section/line]

#### Suggestions (Nice to Have)
- [ ] [Suggestion] - Location: [section/line]

### Context Efficiency Score
[1-5]: [Brief explanation]
- 5: Extremely concise, every word necessary
- 4: Mostly efficient, minor verbosity
- 3: Acceptable, some trimming needed
- 2: Verbose, significant trimming needed
- 1: Bloated, major revision required

### Technical Writing Quality
[1-5]: [Brief explanation]
- 5: Precise, concise, active voice, no filler
- 4: Mostly clear, minor improvements
- 3: Acceptable, some verbosity/vagueness
- 2: Significant clarity issues, passive voice, filler
- 1: Unclear, verbose, imprecise

### Overall Assessment
[Pass/Pass with Recommendations/Needs Revision]

### Specific Improvements
```diff
[Show diffs for suggested changes]
```
```

## Common Skill Smells

### The Encyclopedia
**Symptom:** Exhaustive domain coverage  
**Fix:** Break into focused skills or link to docs

### The CLAUDE.md Duplicate
**Symptom:** Project-specific conventions  
**Fix:** Move to CLAUDE.md, keep domain knowledge in skill

### The Vague Guide
**Symptom:** Generic advice ("write clean code")  
**Fix:** Provide specific, actionable guidance

### The Context Hog
**Symptom:** 1000+ lines, auto-loaded  
**Fix:** Compress, split, or make invokable-only

### The Rigid Workflow
**Symptom:** Overly prescriptive steps  
**Fix:** Provide guidance and checkpoints, allow adaptation

### The Missing Verification
**Symptom:** Implementation without validation  
**Fix:** Add verification steps, success criteria, tests

### The Assumption Maker
**Symptom:** "Update the config" (which file? where?)  
**Fix:** Explicit paths, patterns, or discovery method

### The Verbose Writer
**Symptom:** Filler words, passive voice, redundancy  
**Fix:** Apply technical writing principles

## Examples

### Good Knowledge Skill

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

## Request/Response
- camelCase for JSON properties
- ISO 8601 timestamps: `2024-01-15T10:30:00Z`
- Wrap lists: `{ "data": [...], "meta": { "total": 100 } }`

## Pagination
- Cursor-based for large datasets
- Include `next`, `prev` in meta
- Max 100 items per page

## Error Handling
- Use RFC 7807 Problem Details
- Include `type`, `title`, `status`, `detail`
```

**Why it passes:** Concise, focused, provides patterns Claude can't infer, scannable, no prose.

### Good Workflow Skill

```markdown
---
name: fix-security-issue
description: Fix security vulnerability following our security workflow
disable-model-invocation: true
---

# Fix Security Issue

Fix security issue $ARGUMENTS following our security review process.

## Steps

1. **Analyze vulnerability**
   - `gh issue view $ARGUMENTS` to read security issue
   - Identify CWE category and severity
   - Understand attack vector

2. **Find affected code**
   - Search for vulnerable patterns using Grep
   - Check for similar instances elsewhere
   - Review history: `git log -p --grep="$PATTERN"`

3. **Implement fix**
   - Address root cause, not symptoms
   - Follow secure patterns from `.claude/skills/security-patterns/`
   - Update all affected locations

4. **Write security tests**
   - Test reproduces vulnerability
   - Verify test fails on old code
   - Verify test passes on fixed code
   - Add edge case tests

5. **Validate fix**
   - `npm test`
   - `npm run security-scan`
   - `npm run lint`

6. **Document and commit**
   - Add security comment explaining fix
   - `security: fix [CWE-XXX] in [component]`
   - Reference issue: `Fixes #$ARGUMENTS`

7. **Create PR**
   - `gh pr create --template security`
   - Request @security-team review
   - Add `security` label

## Verification

- [ ] Security test added and passing
- [ ] All tests passing
- [ ] Security scanner clean
- [ ] Similar patterns checked
- [ ] Security team assigned
```

**Why it passes:** Clear workflow, `disable-model-invocation: true`, verification checklist, exact commands, success criteria, uses `$ARGUMENTS`.

### Problematic Skill

```markdown
---
name: make-code-better
description: Improves code quality
---

# Code Improvement Guide

This skill helps you write better, cleaner, more maintainable code.

## General Principles

Always write clean code that is easy to read. Make sure your code 
follows best practices. Remember that code is read more often than 
it's written.

## Things to Consider

- Make your code modular
- Add appropriate comments
- Follow DRY principle
- Use meaningful names
- Keep functions small
- Write tests
- Handle errors
- Optimize performance
- Make it scalable
- Consider security
```

**Why it fails:**
- Too vague (generic advice)
- No actionable steps
- Missing `disable-model-invocation` flag
- Bloated prose
- No verification
- No examples
- Unclear when to use

**Fix:** Split into focused skills (security-patterns, testing-patterns), provide examples, add verification, make context-efficient.

### Technical Writing Improvement

**BEFORE (verbose):**
```markdown
## Error Handling

When working with API calls, it's important to handle errors properly. 
You should catch exceptions and log them so you can debug issues later. 
It's also a good idea to provide meaningful error messages.
```

**AFTER (concise):**
```markdown
## Error Handling

- Catch all exceptions
- Log to monitoring (Sentry, Datadog)
- Return user-friendly messages (hide stack traces)

```javascript
try {
  await api.call()
} catch (error) {
  logger.error('API failed', { error, context })
  throw new UserError('Unable to process request')
}
```
```

**Improvements:** Eliminated filler, active voice, specific tools, added code, 60% shorter with more info.

## References

Based on Claude Code best practices:
- https://code.claude.com/docs/en/best-practices
- https://code.claude.com/docs/en/skills
- https://code.claude.com/docs/en/how-claude-code-works

## Usage

```
/skill-reviewer path/to/SKILL.md
```
