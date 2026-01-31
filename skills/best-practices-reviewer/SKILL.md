---
name: best-practices-reviewer
description: Reviews skills against Claude Code best practices. Use when auditing skill files for adherence to recommendations.
disable-model-invocation: true
aliases:
  - skill-reviewer
  - review-skill
---

# Skill Best Practices Reviewer

Reviews skill files against Claude Code best practices.

**Target:** $ARGUMENTS (path to skill file or directory)

## When to Use This Skill

Use this skill when:
- Creating new skills to validate they follow best practices
- Reviewing existing skills for improvement opportunities
- Auditing skill files before publication or sharing
- Debugging why a skill isn't behaving as expected
- Ensuring skills are context-efficient and performant

## Best Practices Checklist

When reviewing a skill, validate against these criteria:

### 1. Skill Metadata

**Frontmatter Requirements:**
- [ ] Has `name` field (kebab-case, descriptive)
- [ ] Has clear `description` explaining when to use the skill
- [ ] Uses `disable-model-invocation: true` for workflows with side effects
- [ ] Includes `aliases` if the skill has common alternative names

**Quality Indicators:**
- Description is concise (1-2 sentences)
- Description explains WHEN to use the skill, not just what it does
- Name is specific enough to be discoverable but general enough to apply broadly

### 2. Content Structure

**Organization:**
- [ ] Has clear sections with descriptive headers
- [ ] Uses markdown formatting consistently
- [ ] Includes examples where applicable
- [ ] Has a "When to Use" section for context

**Context Efficiency:**
- [ ] Concise and focused - only includes essential information
- [ ] Avoids redundant explanations Claude already knows
- [ ] Uses bullet points and lists for scannability
- [ ] Links to external docs rather than duplicating them
- [ ] No unnecessary prose or filler content

### 3. Workflow Skills (Invokable)

For skills invoked with `/skill-name`:

**Structure:**
- [ ] Uses `disable-model-invocation: true` in frontmatter
- [ ] Clearly numbered steps or phases
- [ ] Each step is actionable and specific
- [ ] Includes verification/validation steps
- [ ] Uses `$ARGUMENTS` variable if it accepts parameters

**Quality:**
- [ ] Steps are ordered logically
- [ ] Includes error handling or fallback guidance
- [ ] Specifies when to ask for user input vs. proceed autonomously
- [ ] Has clear success criteria or completion conditions

### 4. Knowledge Skills (Auto-Applied)

For skills Claude applies automatically when relevant:

**Content:**
- [ ] Focused on domain knowledge Claude can't infer from code
- [ ] Provides patterns, conventions, or architectural guidance
- [ ] Includes code examples where helpful (with language tags)
- [ ] Organized by topic or use case

**Scope:**
- [ ] Not overly broad (narrow skills are more useful than kitchen-sink skills)
- [ ] Not duplicating what's in CLAUDE.md (use CLAUDE.md for project-specific rules)
- [ ] Provides guidance, not rigid instructions

### 5. Tool Usage Guidance

**When skills reference tools:**
- [ ] Recommends the right tool for the job (Read vs Bash cat, Grep vs Bash grep)
- [ ] Suggests parallel tool calls when appropriate
- [ ] Uses subagents for context-heavy exploration
- [ ] Avoids unnecessary tool use (e.g., don't read files Claude doesn't need)

**Context-Saving Patterns:**
- [ ] Encourages focused searches over broad exploration
- [ ] Recommends filtering/scoping before reading large files
- [ ] Uses subagents for investigation tasks
- [ ] Suggests `/clear` when context is cluttered

### 6. Verification & Validation

**Self-Verification:**
- [ ] Includes steps for Claude to verify its work
- [ ] Specifies what success looks like
- [ ] Recommends running tests, linters, or validation commands
- [ ] Addresses root causes, not symptoms

**User Feedback:**
- [ ] Prompts for user confirmation on destructive actions
- [ ] Asks clarifying questions when ambiguity exists
- [ ] Uses `AskUserQuestion` tool appropriately
- [ ] Provides progress updates for long-running tasks

### 7. Code Examples

**If the skill includes code examples:**
- [ ] Examples use correct language syntax highlighting
- [ ] Shows both BAD and GOOD patterns when relevant
- [ ] Includes comments explaining non-obvious code
- [ ] Examples are complete and runnable (not pseudocode fragments)
- [ ] Uses realistic, practical examples (not toy examples)

### 8. Anti-Patterns to Avoid

**Content Issues:**
- ❌ Too long - skills that exceed 500 lines are probably too broad
- ❌ Too vague - generic advice Claude already knows
- ❌ Too rigid - skills should guide, not constrain creativity
- ❌ Duplicates CLAUDE.md - project-specific rules belong there
- ❌ Over-engineering - doesn't add unnecessary complexity

**Workflow Issues:**
- ❌ No verification steps - "implement X" without "test X"
- ❌ Assumes context - doesn't specify where to look for files
- ❌ Unclear scope - "investigate the codebase" without boundaries
- ❌ Missing error handling - doesn't address what to do if steps fail
- ❌ No user interaction - proceeds with destructive actions without confirmation

### 9. Language & Tone

**Technical Writing Principles:**
- [ ] Uses imperative voice for instructions ("Run tests" not "You should run tests")
- [ ] Concise and direct - eliminates filler words and redundancy
- [ ] Precise terminology - uses exact technical terms, avoids ambiguity
- [ ] Active voice preferred over passive voice
- [ ] One idea per sentence for clarity
- [ ] Avoids unnecessary adjectives or superlatives
- [ ] Professional and objective tone
- [ ] No emojis (unless explicitly part of the domain)

**Common Verbosity Patterns to Eliminate:**
- "In order to" → "To"
- "It is important to note that" → (delete, just state the fact)
- "You should" / "You need to" → Use imperative ("Run", "Check", "Verify")
- "Please note that" → (delete)
- "Going forward" / "Moving forward" → (delete)
- "At this point in time" → "Now" or (delete)
- "For the purpose of" → "To" or "For"
- "With regard to" → "About" or "Regarding"

### 10. Maintenance & Evolution

**Sustainability:**
- [ ] Version-agnostic (doesn't reference specific tool versions that change)
- [ ] Links to official documentation for evolving references
- [ ] Includes dates or context for time-sensitive information
- [ ] Can be updated incrementally

## Technical Writing Principles

Maximize conciseness without sacrificing clarity:

### Precision Over Description

**BAD (vague):**
> "Make sure your code is well-organized and follows good practices"

**GOOD (precise):**
> "Use dependency injection. Limit functions to 50 lines."

### Eliminate Filler Words

**Common filler patterns:**
- "basically", "essentially", "generally", "typically"
- "very", "really", "quite", "actually"
- "kind of", "sort of", "a bit"
- "simply", "just", "merely"

**BAD:**
> "You should basically just run the tests to make sure everything is actually working correctly"

**GOOD:**
> "Run tests to verify functionality"

### Use Concrete Numbers and Specifics

**BAD:**
> "Keep functions small and avoid deeply nested code"

**GOOD:**
> "Limit functions to 50 lines. Limit nesting to 3 levels."

### Prefer Active Voice

**BAD (passive):**
> "The configuration should be validated before the application is started"

**GOOD (active):**
> "Validate configuration before starting the application"

### Front-Load Important Information

**BAD:**
> "When you're working with user input, which could potentially contain malicious data, it's important to remember that you should always validate and sanitize it"

**GOOD:**
> "Always validate and sanitize user input"

### Use Parallel Structure

**BAD (inconsistent):**
- Check that the file exists
- Making sure permissions are correct
- You should verify the contents

**GOOD (parallel):**
- Check file exists
- Verify permissions
- Validate contents

### Delete Hedge Words

**BAD:**
> "This might help improve performance somewhat"

**GOOD:**
> "This improves performance by 30%"

Or if uncertain:
> "This may improve performance. Benchmark to verify."

## Review Process

When reviewing a skill:

1. **Read the skill** at $ARGUMENTS to understand purpose and scope
2. **Check frontmatter** for required fields and appropriate flags
3. **Evaluate context efficiency** - is every sentence necessary?
4. **Apply technical writing check** - concise, precise, active voice
5. **Verify structure** - clear sections, logical flow, scannable format
6. **Test examples** - are code examples correct and complete?
7. **Check for anti-patterns** - does it avoid common mistakes?
8. **Assess scope** - is it focused enough? Too broad?
9. **Validate verification** - does it include ways for Claude to check its work?

## Output Format

Provide review results in this format:

```markdown
## Skill Review: [skill-name]

### Summary
[1-2 sentence overview of the skill's purpose and overall quality]

### Strengths
- [What the skill does well]
- [Effective patterns or structure]

### Issues Found

#### Critical Issues (Must Fix)
- [ ] [Issue description] - Location: [section/line]
- [ ] [Issue description] - Location: [section/line]

#### Recommendations (Should Fix)
- [ ] [Recommendation] - Location: [section/line]
- [ ] [Recommendation] - Location: [section/line]

#### Suggestions (Nice to Have)
- [ ] [Suggestion] - Location: [section/line]

### Context Efficiency Score
[Rating 1-5]: [Brief explanation]
- 5: Extremely concise, every word necessary
- 4: Mostly efficient, minor verbosity
- 3: Acceptable, some areas could be tightened
- 2: Verbose, significant trimming needed
- 1: Bloated, major revision required

### Technical Writing Quality
[Rating 1-5]: [Brief explanation]
- 5: Precise, concise, active voice, no filler
- 4: Mostly clear, minor improvements needed
- 3: Acceptable, some verbosity or vagueness
- 2: Significant clarity issues, passive voice, filler words
- 1: Unclear, verbose, imprecise terminology

### Overall Assessment
[Pass/Pass with Recommendations/Needs Revision]

### Specific Improvements

```diff
[Show specific diffs for suggested changes if applicable]
```
```

## Common Skill Smells

Watch for these indicators of poorly-designed skills:

### The Encyclopedia Skill
**Symptom:** Skill tries to cover an entire domain in exhaustive detail
**Fix:** Break into focused, topic-specific skills or link to external docs

### The CLAUDE.md Duplicate
**Symptom:** Skill contains project-specific conventions
**Fix:** Move project-specific rules to CLAUDE.md, keep skills for domain knowledge

### The Vague Guide
**Symptom:** Generic advice like "write clean code" or "follow best practices"
**Fix:** Provide specific, actionable guidance Claude can't infer

### The Context Hog
**Symptom:** Skill is loaded automatically but contains 1000+ lines
**Fix:** Compress, split into multiple skills, or make it invokable-only

### The Rigid Workflow
**Symptom:** Overly prescriptive steps that don't allow for adaptation
**Fix:** Provide guidance and checkpoints, not rigid sequences

### The Missing Verification
**Symptom:** Implementation steps without validation or testing
**Fix:** Add verification steps, success criteria, test commands

### The Assumption Maker
**Symptom:** "Update the config file" without specifying which file or where
**Fix:** Be explicit about file paths, patterns, or how to find them

### The Verbose Writer
**Symptom:** Excessive filler words, passive voice, redundant explanations
**Fix:** Apply technical writing principles - concise, precise, active voice

## Example Reviews

### Example 1: Good Knowledge Skill

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

## Error Handling
- Use RFC 7807 Problem Details
- Include `type`, `title`, `status`, `detail`
```

**Review:** ✅ Pass
- Concise and focused
- Provides patterns Claude can't infer
- Scannable format
- No unnecessary prose
- Context-efficient

### Example 2: Good Workflow Skill

```markdown
---
name: fix-security-issue
description: Fix a security vulnerability following our security workflow
disable-model-invocation: true
---

# Fix Security Issue

Fix security issue $ARGUMENTS following our security review process.

## Steps

1. **Analyze the vulnerability**
   - Use `gh issue view $ARGUMENTS` to read the security issue
   - Identify CWE category and severity
   - Understand the attack vector

2. **Find affected code**
   - Search for vulnerable patterns using Grep
   - Check for similar instances elsewhere in codebase
   - Review recent git history: `git log -p --grep="$PATTERN"`

3. **Implement the fix**
   - Address root cause, not symptoms
   - Follow secure coding patterns from `.claude/skills/security-patterns/`
   - Update all affected locations

4. **Write security tests**
   - Create test that reproduces the vulnerability
   - Verify the test fails on the old code
   - Verify the test passes on the fixed code
   - Add test for edge cases

5. **Validate the fix**
   - Run full test suite: `npm test`
   - Run security scanner: `npm run security-scan`
   - Check for regressions: `npm run lint`

6. **Document and commit**
   - Add security comment explaining the fix
   - Commit with security prefix: `security: fix [CWE-XXX] in [component]`
   - Reference issue in commit: `Fixes #$ARGUMENTS`

7. **Create PR for security review**
   - Use security PR template: `gh pr create --template security`
   - Request review from @security-team
   - Add `security` label

## Verification

- [ ] Security test added and passing
- [ ] All tests passing
- [ ] Security scanner shows no issues
- [ ] Similar patterns checked across codebase
- [ ] Security team assigned for review
```

**Review:** ✅ Pass
- Clear numbered workflow
- Uses `disable-model-invocation: true` correctly
- Includes verification checklist
- Specifies exact commands
- Has clear success criteria
- Uses `$ARGUMENTS` appropriately

### Example 3: Problematic Skill (Needs Revision)

```markdown
---
name: make-code-better
description: Improves code quality
---

# Code Improvement Guide

This skill helps you write better, cleaner, more maintainable code that follows industry best practices and modern software engineering principles.

## General Principles

Always write clean code that is easy to read and understand. Make sure your code follows best practices and design patterns. Remember that code is read more often than it's written, so prioritize readability.

## Things to Consider

- Make your code modular and reusable
- Add appropriate comments
- Follow the DRY principle
- Use meaningful variable names
- Keep functions small
- Write tests
- Handle errors properly
- Optimize for performance
- Make it scalable
- Consider security
- Think about maintainability
...
```

**Review:** ❌ Needs Revision

**Critical Issues:**
- Too vague - generic advice Claude already knows
- No actionable steps or specific patterns
- Missing `disable-model-invocation` flag (unclear when to use)
- Bloated prose without substance
- No verification or validation guidance
- No code examples
- Unclear when this applies vs. other guidance

**Recommendations:**
- Split into focused skills (security-patterns, testing-patterns, etc.)
- Provide specific, actionable examples
- Add code snippets showing BAD vs. GOOD
- Include verification commands
- Make it context-efficient
- Add clear "When to Use" section

### Example 4: Technical Writing Improvements

**BEFORE (verbose, vague):**
```markdown
## Error Handling

When you're working with API calls, it's really important to note that you
should always make sure to handle errors properly. Basically, you need to
catch exceptions and then you should log them appropriately so that you can
debug issues later. It's also a good idea to provide meaningful error messages
to users so they understand what went wrong.

In order to handle errors effectively, you should consider implementing a
centralized error handling mechanism that can be used throughout your application.
```

**AFTER (concise, precise):**
```markdown
## Error Handling

**API Error Handling:**
- Catch all exceptions
- Log to monitoring system (Sentry, Datadog)
- Return user-friendly messages (hide stack traces)

**Implementation:**
```javascript
try {
  await api.call()
} catch (error) {
  logger.error('API call failed', { error, context })
  throw new UserError('Unable to process request. Try again.')
}
```

**Centralized Handler:**
- Create `errorHandler.js` middleware
- Apply globally in `app.js`
```

**Improvements:**
- Eliminated filler: "it's important to note", "basically", "really"
- Active voice: "Catch" vs "you should catch"
- Specific: "Sentry, Datadog" vs "log appropriately"
- Code example instead of prose description
- 60% reduction in word count while adding more information

## References

Based on official Claude Code best practices:
- https://code.claude.com/docs/en/best-practices
- https://code.claude.com/docs/en/skills
- https://code.claude.com/docs/en/how-claude-code-works

## Usage Examples

### Review a skill file
```
/best-practices-reviewer .claude/skills/my-skill/SKILL.md
```

### Review all skills
```
Review all skill files in .claude/skills/ using the best-practices-reviewer
```

### Quick validation
```
Use /best-practices-reviewer to check if this skill follows best practices [paste skill content]
```
