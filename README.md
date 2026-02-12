<p align="center" width="100%">
    <img width="50%" src="grimbard.png" alt="grimbard logo" title="grimbard logo">
</p>

# grimbard
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)

**77 security skills for AI agents** — anti-patterns, security patterns, static analysis tools, and code review workflows for Claude Code, Cursor, Windsurf, Gemini CLI, and 30+ other agents.

Built by a pentester and secure code reviewer. Battle-tested in real engagements.

## Quick Start

```bash
npx skills add igbuend/grimbard
```

That's it. Your AI agent now has 77 security skills covering:
- **38 security anti-patterns** — detect vulnerable code (XSS, SQLi, command injection, etc.)
- **21 security patterns** — implement secure designs (authentication, encryption, etc.)
- **10 static analysis tool skills** — run and interpret SAST tools
- **4 review & discovery skills** — SARIF triage, attack surface mapping, codebase discovery
- **3 quality assurance skills** — review agents, skills, and sub-agents
- **1 ethics skill** — responsible disclosure and legal frameworks

### Try it

After installing, ask your AI agent:

```
Review this file for security vulnerabilities
```

The agent automatically loads the relevant anti-pattern skills based on the code context — XSS patterns for HTML rendering, SQLi patterns for database queries, etc.

## What's Included

### Security Anti-Patterns (38 skills)

Each skill provides BAD (vulnerable) and GOOD (secure) code examples to help AI agents identify and fix security vulnerabilities.

| Skill | CWE | Description |
|-------|-----|-------------|
| `command-injection` | CWE-78 | Shell command string concatenation |
| `sql-injection` | CWE-89 | SQL query string building |
| `xss` | CWE-79 | Cross-site scripting (reflected, stored, DOM) |
| `path-traversal` | CWE-22 | Directory traversal via user input |
| `hardcoded-secrets` | CWE-798 | Credentials in source code |
| `missing-authentication` | CWE-306 | Unprotected endpoints |
| `missing-input-validation` | CWE-20 | Unvalidated user input |
| `jwt-misuse` | CWE-347 | JWT implementation flaws |
| `open-cors` | CWE-942 | Overly permissive CORS |
| `mass-assignment` | CWE-915 | Unfiltered object binding |
| `dom-clobbering` | CWE-79 | HTML injection overwrites JS globals |
| `encoding-bypass` | CWE-838 | Validation before normalization |
| `mutation-xss` | CWE-79 | Sanitizer bypass via parser mutations |
| `missing-security-headers` | CWE-16 | Missing CSP, HSTS, X-Frame-Options |
| `session-fixation` | CWE-384 | Session ID not rotated after login |
| `insecure-defaults` | CWE-276 | Unsafe default configurations |
| `weak-encryption` | CWE-327 | Broken or weak crypto algorithms |
| `weak-password-hashing` | CWE-916 | MD5/SHA1 for passwords |
| `unrestricted-file-upload` | CWE-434 | Dangerous file upload handling |
| `verbose-error-messages` | CWE-209 | Stack traces in production |
| `log-injection` | CWE-117 | Unsanitized data in log entries |
| `debug-mode-production` | CWE-489 | Debug features in production |
| `excessive-data-exposure` | CWE-200 | Over-sharing in API responses |
| `missing-rate-limiting` | CWE-770 | No throttling on sensitive endpoints |
| `hallucinated-packages` | CWE-829 | AI-invented dependency names |
| `oauth-security` | CWE-346 | OAuth/OIDC implementation flaws |
| `redos` | CWE-1333 | Catastrophic regex backtracking |
| `timing-attacks` | CWE-208 | Non-constant-time comparisons |
| `integer-overflow` | CWE-190 | Arithmetic overflow/underflow |
| `type-confusion` | CWE-843 | Type mismatch vulnerabilities |
| `unicode-security` | CWE-176 | Unicode normalization attacks |
| `ldap-injection` | CWE-90 | LDAP query injection |
| `xpath-injection` | CWE-643 | XPath query injection |
| `second-order-injection` | CWE-74 | Stored data used unsafely later |
| `padding-oracle` | CWE-649 | Padding oracle cryptographic attacks |
| `length-extension-attacks` | CWE-328 | Hash length extension |
| `insecure-temp-files` | CWE-377 | Predictable temp file paths |
| `insufficient-randomness` | CWE-330 | Weak random number generation |

### Security Patterns (21 skills)

Secure design patterns from [DistriNet Research](https://securitypatterns.distrinet-research.be/). Each pattern explains when to use it, how to implement it, and what to watch out for.

| Category | Patterns |
|----------|----------|
| **Authentication** | Password-based, Opaque token, Verifiable token (JWT), Session-based access control |
| **Cryptography** | Encryption, Digital signature, MAC, Key management, Crypto-as-a-service, Self-managed crypto, Cryptographic action |
| **Data Protection** | Selective encrypted storage, Selective encrypted transmission, Transparent encrypted storage, Encrypted tunnel |
| **Access Control** | Authorisation, Session-based access control |
| **Input/Output** | Data validation, Output filter |
| **Operations** | Limit request rate, Log entity actions |

### Static Analysis Tools (10 skills)

Skills that teach AI agents how to run and interpret results from security tools:

| Tool | Purpose |
|------|---------|
| **Opengrep** | Pattern-based SAST (open-source Semgrep fork) |
| **Semgrep** | Pattern-based SAST |
| **Gitleaks** | Secrets and credential detection |
| **KICS** | Infrastructure-as-Code security |
| **Noir** | API endpoint and attack surface discovery |
| **OSV-Scanner** | Dependency vulnerability scanning |
| **Depscan** | Advanced SCA with SBOM/VDR |
| **Application Inspector** | Technology profiling |
| **CodeQL** | Deep cross-file static analysis |
| **Trivy** | Container and dependency scanning |

### Other Skills

| Skill | Description |
|-------|-------------|
| **SARIF Issue Reporter** | Triage and report SARIF findings from any tool |
| **Attack Surface XSS** | XSS-focused attack surface analysis |
| **Codebase Discovery** | Repository structure and technology mapping |
| **Content Security Policy** | CSP header analysis and bypass detection |
| **Ethical Hacking Ethics** | Legal frameworks, responsible disclosure, platform rules |
| **Skill Reviewer** | Review quality of other skills |
| **Agent Review** | Review agent configurations |
| **Sub-Agent Review** | Review sub-agent setups |

## Full Agent (Optional)

For the complete security review workflow with automated tool orchestration, clone the repo and use it with Claude Code:

```bash
git clone https://github.com/igbuend/grimbard.git
cd grimbard
```

The agent provides structured workflows:
- `/grimbard-review` — Full 6-phase security review (4-8 hours)
- `/grimbard-quick` — Quick automated scan (15-30 min)
- `/grimbard-triage` — Prioritize existing SARIF findings
- `/grimbard-compliance` — PCI-DSS, HIPAA, SOC2, GDPR audit

See [agents/grimbard/AGENT.md](agents/grimbard/AGENT.md) for full documentation.

### DevContainer

A DevContainer is included for development with all tools pre-installed. Open the repo in VS Code with the Remote Containers extension, or use GitHub Codespaces.

## FAQ

### Why the name **grimbard**?

Grimbard is the badger in the medieval fable of [**Reynard the Fox**](https://en.wikipedia.org/wiki/Reynard_the_Fox) — a loyal supporter, defender and advisor of the cunning fox. Grimbard represents wisdom, counsel and trustworthy guidance. Perfect for a repository of security patterns and knowledge.

Grimbard also gives the advice to the wrong person. Whether that's you or the AI is for you to decide.

### How do skills work?

When you ask your AI agent a security-related question, it:

1. **Identifies the relevant pattern(s)** based on your question
2. **Loads the pattern knowledge** from the SKILL.md file
3. **Applies the pattern** to your specific context
4. **Provides implementation guidance** tailored to your codebase

### Should I install all skills?

Yes — they're lightweight (just markdown). The AI only loads relevant skills when needed. Having all of them available means the AI can catch more issues across your codebase.

### Do these help with compliance?

Yes. The patterns cover requirements from PCI-DSS, HIPAA, GDPR, and SOC 2. However, compliance requires more than technical controls — consult compliance experts.

### I found a mistake / want to improve something

Please open a [GitHub issue](https://github.com/igbuend/grimbard/issues) or submit a pull request.

## Roadmap

- **v1.0** — All skills fully tested and validated
- **v2.0** — AI agent with orchestrated tool execution
- **v3.0** — The AIs will decide by then

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/igbuend)

## Licensing

The code in this project is licensed under the [MIT license](LICENSE).

The documents (e.g. markdown files) in this project are licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/).

The security pattern skills were created from [Security Pattern Catalogue - DistriNet Research](https://securitypatterns.distrinet-research.be/). The [Gitlab repo](https://gitlab.kuleuven.be/distrinet/research/security-patterns/security-pattern-catalogue) is licensed under a [Creative Commons Attribution Non Commercial Share Alike 4.0 International License](https://creativecommons.org/licenses/by-nc-sa/4.0/).

The anti-pattern skills were created from [sec-context](https://github.com/Arcanum-Sec/sec-context) by [Arcanum Security](https://arcanum-sec.com/). The repository does not contain any copyright information (which legally means it is copyrighted by default). Awaiting clarification, but consider this work a derivative (IANAL).

Some skills are modified versions from the [Trail of Bits Skills Marketplace](https://github.com/trailofbits/skills), licensed under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).
