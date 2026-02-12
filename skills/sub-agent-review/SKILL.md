---
name: sub-agent-review
description: Review Claude Code sub-agent implementations for best practices in configuration, tool access, hooks, and delegation patterns. Use when creating, auditing, or optimizing sub-agents.
disable-model-invocation: true
aliases:
  - subagent-review
  - review-subagent
  - agent-config-review
---

# Sub-Agent Implementation Review

Review Claude Code sub-agent configurations for best practices.

**Target:** $ARGUMENTS (path to sub-agent file or agents directory)

## When to Use This Skill

- Creating new sub-agents
- Auditing existing sub-agent configurations
- Optimizing sub-agent performance and cost
- Reviewing tool access and permissions
- Implementing sub-agent hooks

## Review Process

1. **Discover** - Find agent files at $ARGUMENTS (`.claude/agents/` or `~/.claude/agents/`)
2. **Validate** - Check frontmatter and configuration
3. **Evaluate** - Score against best practices
4. **Report** - Generate findings with recommendations

## Sub-Agent File Structure

### File Format

Sub-agents are Markdown files with YAML frontmatter:

```markdown
---
name: code-reviewer
description: Reviews code for quality and best practices
tools: Read, Glob, Grep
model: sonnet
---

You are a code reviewer. When invoked, analyze the code and provide
specific, actionable feedback on quality, security, and best practices.
```

### Storage Locations

| Location | Scope | Priority | Use Case |
|----------|-------|----------|----------|
| `--agents` CLI flag | Session only | 1 (highest) | Testing, automation |
| `.claude/agents/` | Project | 2 | Team-shared agents |
| `~/.claude/agents/` | User | 3 | Personal agents |
| Plugin `agents/` | Plugin scope | 4 (lowest) | Distributed agents |

## Frontmatter Configuration

### Required Fields

| Field | Description | Example |
|-------|-------------|---------|
| `name` | Unique identifier (kebab-case) | `code-reviewer` |
| `description` | When Claude should delegate | `Reviews code for quality. Use proactively after code changes.` |

### Optional Fields

| Field | Description | Default |
|-------|-------------|---------|
| `tools` | Allowed tools (allowlist) | Inherits all |
| `disallowedTools` | Denied tools (denylist) | None |
| `model` | `sonnet`, `opus`, `haiku`, `inherit` | `inherit` |
| `permissionMode` | Permission handling | `default` |
| `skills` | Skills to preload | None |
| `hooks` | Lifecycle hooks | None |

## Configuration Checklist

### 1. Naming & Description

- [ ] Name is kebab-case and descriptive
- [ ] Description explains WHEN to use the agent
- [ ] Description includes "use proactively" if auto-delegation desired
- [ ] Description is specific enough for accurate delegation

**BAD:**
```yaml
name: helper
description: Helps with stuff
```

**GOOD:**
```yaml
name: code-reviewer
description: Expert code review specialist. Proactively reviews code for quality, security, and maintainability. Use immediately after writing or modifying code.
```

### 2. Tool Access

- [ ] Only necessary tools are granted
- [ ] Read-only agents exclude Write/Edit
- [ ] Dangerous tools require justification
- [ ] MCP tools considered if needed

**Tool Categories:**

| Category | Tools | Use Case |
|----------|-------|----------|
| **Read-only** | Read, Glob, Grep | Research, review |
| **Modification** | Write, Edit | Implementation |
| **Execution** | Bash | Commands, builds |
| **All** | (inherited) | Full capability |

**GOOD (read-only reviewer):**
```yaml
tools: Read, Grep, Glob, Bash
disallowedTools: Write, Edit
```

### 3. Model Selection

- [ ] Model matches task complexity
- [ ] Cost-sensitive tasks use Haiku
- [ ] Complex reasoning uses Sonnet/Opus
- [ ] `inherit` used when parent model is appropriate

| Model | Best For | Cost |
|-------|----------|------|
| `haiku` | Fast searches, simple tasks | Low |
| `sonnet` | Balanced capability/speed | Medium |
| `opus` | Complex reasoning | High |
| `inherit` | Match parent context | Varies |

### 4. Permission Modes

- [ ] Permission mode matches use case
- [ ] `bypassPermissions` used only when necessary
- [ ] `dontAsk` used for non-interactive agents

| Mode | Behavior | Use Case |
|------|----------|----------|
| `default` | Standard prompts | Interactive agents |
| `acceptEdits` | Auto-accept edits | Trusted modifiers |
| `dontAsk` | Auto-deny prompts | Background agents |
| `bypassPermissions` | Skip all checks | Automation (dangerous) |
| `plan` | Read-only exploration | Research agents |

### 5. System Prompt Quality

- [ ] Prompt is focused and specific
- [ ] Clear workflow/steps defined
- [ ] Output format specified
- [ ] Constraints stated explicitly
- [ ] No unnecessary verbosity

**Prompt Structure:**
```markdown
---
[frontmatter]
---

[Role statement - who the agent is]

When invoked:
1. [First step]
2. [Second step]
3. [Third step]

[Detailed guidelines]

[Output format specification]
```

### 6. Skills Preloading

- [ ] Only necessary skills preloaded
- [ ] Skills match agent's domain
- [ ] No duplicate/conflicting skills

```yaml
skills:
  - api-conventions
  - error-handling-patterns
```

### 7. Hooks Configuration

- [ ] Hooks validate dangerous operations
- [ ] Hook scripts are executable
- [ ] Exit codes used correctly
- [ ] Hooks don't block legitimate operations

**Hook Exit Codes:**

| Code | Behavior |
|------|----------|
| 0 | Allow operation |
| 1 | Error (operation continues) |
| 2 | Block operation |

**Example: Validate SQL queries**
```yaml
hooks:
  PreToolUse:
    - matcher: "Bash"
      hooks:
        - type: command
          command: "./scripts/validate-readonly-query.sh"
```

## Best Practices

### Design Principles

| Principle | Description |
|-----------|-------------|
| **Single Purpose** | Each agent excels at one specific task |
| **Minimal Tools** | Grant only necessary permissions |
| **Clear Delegation** | Description enables accurate auto-delegation |
| **Version Control** | Project agents checked into repo |

### When to Use Sub-Agents vs Main Conversation

**Use Sub-Agents:**
- Task produces verbose output (tests, logs, docs)
- Need specific tool restrictions
- Work is self-contained
- Can return a summary

**Use Main Conversation:**
- Frequent back-and-forth needed
- Multiple phases share context
- Quick, targeted changes
- Latency matters

### Common Patterns

#### 1. Isolate High-Volume Operations

```
Use a subagent to run the test suite and report only failing tests
```

#### 2. Parallel Research

```
Research auth, database, and API modules in parallel using separate subagents
```

#### 3. Chain Sub-Agents

```
Use code-reviewer to find issues, then use fixer to resolve them
```

### Foreground vs Background

| Mode | Permissions | Questions | Use Case |
|------|-------------|-----------|----------|
| **Foreground** | Interactive prompts | Passed through | Complex tasks |
| **Background** | Pre-approved only | Auto-denied | Parallel work |

## Anti-Patterns

| Anti-Pattern | Problem | Fix |
|--------------|---------|-----|
| **God Agent** | Does everything | Split by responsibility |
| **Vague Description** | Wrong delegation | Be specific about when to use |
| **Over-Permissioned** | Security risk | Limit tools to necessary |
| **Missing Hooks** | Unsafe operations | Add validation hooks |
| **Hardcoded Model** | Inflexible | Use `inherit` unless specific need |
| **No Constraints** | Unpredictable | Define clear boundaries in prompt |
| **Verbose Prompt** | Context waste | Keep focused and specific |

## Review Output Format

```markdown
## Sub-Agent Review: [agent-name]

### Summary
[1-2 sentence overview]

### Configuration Score

| Category | Score | Notes |
|----------|-------|-------|
| Naming & Description | X/5 | |
| Tool Access | X/5 | |
| Model Selection | X/5 | |
| Permission Mode | X/5 | |
| System Prompt | X/5 | |
| Hooks | X/5 | |
| **Overall** | **X/5** | |

### Critical Issues
- [ ] [Issue] - Location: [field]

### Recommendations
- [ ] [Recommendation] - Priority: [High/Medium/Low]

### Strengths
- [What the configuration does well]
```

## Built-in Sub-Agents Reference

| Agent | Model | Tools | Purpose |
|-------|-------|-------|---------|
| **Explore** | Haiku | Read-only | Fast codebase search |
| **Plan** | Inherit | Read-only | Research for planning |
| **general-purpose** | Inherit | All | Complex multi-step tasks |
| **Bash** | Inherit | Bash | Terminal commands |
| **Claude Code Guide** | Haiku | Read-only | Help with features |

## Plugin-Packaged Sub-Agents

When distributing sub-agents as part of a Claude Code plugin, additional configuration applies.

### Plugin Directory Structure

```
my-plugin/
├── .claude-plugin/
│   └── plugin.json          # Plugin manifest (only manifest here)
├── agents/                   # Sub-agents at plugin root
│   ├── security-reviewer.md
│   ├── performance-tester.md
│   └── compliance-checker.md
├── skills/                   # Supporting skills
├── hooks/                    # Hook configurations
└── scripts/                  # Hook scripts
```

**Critical:** Agents directory must be at plugin root, not inside `.claude-plugin/`.

### Plugin Agent Frontmatter

Plugin agents support additional frontmatter fields:

```markdown
---
description: What this agent specializes in
capabilities: ["task1", "task2", "task3"]
---

# Agent Name

Detailed description of the agent's role and when Claude should invoke it.

## Capabilities
- Specific task the agent excels at
- Another specialized capability

## Context and examples
When this agent should be used and what problems it solves.
```

| Field | Description | Example |
|-------|-------------|---------|
| `description` | Agent specialization | `Security code review specialist` |
| `capabilities` | Task list for delegation | `["security-review", "vulnerability-scan"]` |

### Plugin Manifest Configuration

In `plugin.json`, specify custom agent paths:

```json
{
  "name": "security-agents",
  "version": "1.0.0",
  "agents": "./custom/agents/"
}
```

Path options:
- Default: `agents/` directory auto-discovered
- Custom: `"agents": "./custom-agents/"` or `"agents": ["./agents/reviewer.md", "./agents/tester.md"]`

### Plugin Agent Hooks

Plugin hooks can respond to sub-agent lifecycle events:

| Event | Trigger | Use Case |
|-------|---------|----------|
| `SubagentStart` | Sub-agent begins | Logging, initialization |
| `SubagentStop` | Sub-agent attempts to stop | Cleanup, validation |

```json
{
  "hooks": {
    "SubagentStart": [
      {
        "hooks": [{
          "type": "command",
          "command": "${CLAUDE_PLUGIN_ROOT}/scripts/log-agent-start.sh"
        }]
      }
    ]
  }
}
```

### Plugin Agent Checklist

- [ ] Agents at plugin root (not in `.claude-plugin/`)
- [ ] Uses `${CLAUDE_PLUGIN_ROOT}` for script paths
- [ ] Hook scripts are executable (`chmod +x`)
- [ ] `capabilities` array aids delegation accuracy
- [ ] Plugin manifest validates with `/plugin validate`

### Plugin Integration Points

| Integration | Behavior |
|-------------|----------|
| `/agents` interface | Plugin agents appear alongside built-in agents |
| Auto-invocation | Claude delegates based on `description` and `capabilities` |
| Manual invocation | Users can invoke plugin agents directly |
| Coexistence | Plugin agents work alongside built-in and user agents |

### Plugin Anti-Patterns

| Anti-Pattern | Problem | Fix |
|--------------|---------|-----|
| Agents in `.claude-plugin/` | Not discovered | Move to plugin root |
| Absolute paths in hooks | Breaks on install | Use `${CLAUDE_PLUGIN_ROOT}` |
| Missing `capabilities` | Poor auto-delegation | Add capability list |
| Non-executable scripts | Hooks fail silently | Run `chmod +x` |

## Example: Well-Configured Sub-Agent

```markdown
---
name: code-reviewer
description: Expert code review specialist. Proactively reviews code for quality, security, and maintainability. Use immediately after writing or modifying code.
tools: Read, Grep, Glob, Bash
model: inherit
---

You are a senior code reviewer ensuring high standards of code quality and security.

When invoked:
1. Run git diff to see recent changes
2. Focus on modified files
3. Begin review immediately

Review checklist:
- Code is clear and readable
- Functions and variables are well-named
- No duplicated code
- Proper error handling
- No exposed secrets or API keys
- Input validation implemented
- Good test coverage
- Performance considerations addressed

Provide feedback organized by priority:
- Critical issues (must fix)
- Warnings (should fix)
- Suggestions (consider improving)

Include specific examples of how to fix issues.
```

## References

- [Claude Code Sub-Agents Documentation](https://code.claude.com/docs/en/sub-agents)
- [Claude Code Plugins Reference](https://code.claude.com/docs/en/plugins-reference)
- [Claude Code Hooks](https://code.claude.com/docs/en/hooks)
- [Claude Code Skills](https://code.claude.com/docs/en/skills)
- [Claude Code Plugins](https://code.claude.com/docs/en/plugins)
