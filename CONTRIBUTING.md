# Contributing to Grimbard

Thanks for your interest in improving Grimbard! Whether it's fixing a typo, adding a new anti-pattern, or improving an existing skill — contributions are welcome.

## Quick Start

```bash
git clone https://github.com/igbuend/grimbard.git
cd grimbard
pre-commit install
```

## Adding a New Skill

### Anti-Pattern Skills

1. Create a directory: `skills/<name>-anti-pattern/`
2. Create `SKILL.md` with this frontmatter:

```yaml
---
name: "<name>-anti-pattern"
description: "Security anti-pattern for <vulnerability> (CWE-XXX). Use when..."
---
```

3. Include these sections:
   - **Summary** — what the vulnerability is
   - **The Anti-Pattern** — what developers do wrong
   - **BAD Code Example** — vulnerable code with comments
   - **GOOD Code Example** — secure code with comments
   - **Detection** — how to spot it in code reviews
   - **References** — CWE link, OWASP, relevant resources

### Security Pattern Skills

1. Create a directory: `skills/<name>-pattern/`
2. Create `SKILL.md` with frontmatter:

```yaml
---
name: "<name>-pattern"
description: "Security pattern for <purpose>. Use when..."
---
```

3. Include: When to Use, Core Components, Implementation, Pitfalls, References.

### Tool Skills

1. Create a directory: `skills/<tool-name>/`
2. Include: Installation, Commands, Usage Examples, CI/CD Integration, References.

## Naming Conventions

| Type | Directory Name | Frontmatter `name` |
|------|---------------|---------------------|
| Anti-pattern | `<name>-anti-pattern/` | `<name>-anti-pattern` |
| Security pattern | `<name>-pattern/` | `<name>-pattern` |
| Tool | `<tool-name>/` | `<tool-name>` |

**The `name` in SKILL.md frontmatter must match the directory name exactly.**

## Updating Existing Skills

- Keep the existing structure and format
- Add code examples in multiple languages where possible
- Include CWE/OWASP references
- Test that frontmatter parses correctly

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add <name> anti-pattern skill
fix: correct CWE reference in sql-injection-anti-pattern
docs: improve installation section in opengrep skill
```

## Pull Requests

1. Fork the repo
2. Create a feature branch (`git checkout -b feat/new-skill`)
3. Make your changes
4. Run `pre-commit run --all-files`
5. Submit a PR with a clear description

## Code of Conduct

Be respectful. We're all here to make security tooling better.

## Licensing

- **Code**: [MIT License](LICENSE)
- **Documentation/Skills**: [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/)

By contributing, you agree that your contributions will be licensed under the same terms.

## Questions?

Open a [GitHub Discussion](https://github.com/igbuend/grimbard/discussions) or [Issue](https://github.com/igbuend/grimbard/issues).
