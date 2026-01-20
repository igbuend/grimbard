# Security Anti-Patterns Skills

Security anti-patterns that human or AI-generated code commonly exhibits. Each skill provides BAD (vulnerable) and GOOD (secure) pseudocode patterns to help identify and fix security vulnerabilities.

## Overview

These 37 anti-pattern skills are extracted from research on AI-generated code vulnerabilities:

- **86%** of AI-generated code fails XSS defenses
- **5-21%** of AI-suggested packages don't exist (slopsquatting)
- AI code is **2.74x more likely** to have XSS vulnerabilities
- SQL injection patterns appeared thousands of times in AI training data

## Skills by Severity

### Critical Severity

| Skill | CWE | Description |
|-------|-----|-------------|
| [hallucinated-packages](./hallucinated-packages/) | CWE-1357 | AI suggests non-existent packages |
| [xss](./xss/) | CWE-79 | Cross-site scripting (Reflected/Stored/DOM) |
| [hardcoded-secrets](./hardcoded-secrets/) | CWE-798 | Credentials embedded in source code |
| [sql-injection](./sql-injection/) | CWE-89 | Unsanitized input in SQL queries |
| [missing-authentication](./missing-authentication/) | CWE-287 | Unprotected endpoints |
| [command-injection](./command-injection/) | CWE-78 | Unsanitized input in shell commands |
| [unrestricted-file-upload](./unrestricted-file-upload/) | CWE-434 | No validation on uploaded files |

### High Severity

| Skill | CWE | Description |
|-------|-----|-------------|
| [missing-input-validation](./missing-input-validation/) | CWE-20 | No type/length/format validation |
| [insufficient-randomness](./insufficient-randomness/) | CWE-330 | Weak random for security tokens |
| [missing-rate-limiting](./missing-rate-limiting/) | CWE-770 | No request throttling |
| [excessive-data-exposure](./excessive-data-exposure/) | CWE-200 | Returning more data than needed |
| [path-traversal](./path-traversal/) | CWE-22 | Directory traversal attacks |
| [weak-password-hashing](./weak-password-hashing/) | CWE-327 | MD5/SHA1 instead of bcrypt/argon2 |
| [debug-mode-production](./debug-mode-production/) | CWE-215 | Debug enabled in production |
| [weak-encryption](./weak-encryption/) | CWE-326 | Outdated algorithms or modes |
| [session-fixation](./session-fixation/) | CWE-384 | Session ID not regenerated |
| [jwt-misuse](./jwt-misuse/) | CWE-287 | Weak JWT secrets or algorithms |
| [mass-assignment](./mass-assignment/) | CWE-915 | Uncontrolled property binding |
| [ldap-injection](./ldap-injection/) | CWE-90 | Unsanitized LDAP filters |
| [xpath-injection](./xpath-injection/) | CWE-643 | Unsanitized XPath queries |

### Medium Severity

| Skill | CWE | Description |
|-------|-----|-------------|
| [log-injection](./log-injection/) | CWE-117 | Unsanitized data in logs |
| [missing-security-headers](./missing-security-headers/) | CWE-16 | No CSP, HSTS, X-Frame-Options |
| [open-cors](./open-cors/) | CWE-346 | Wildcard CORS origins |
| [insecure-temp-files](./insecure-temp-files/) | CWE-377 | Predictable temp file paths |
| [verbose-error-messages](./verbose-error-messages/) | CWE-209 | Stack traces exposed to users |

## Advanced Security Anti-Patterns

These 12 advanced skills cover edge cases, sophisticated attack vectors, and specialized vulnerabilities that require deeper security knowledge.

### Advanced Injection Patterns

| Skill | CWE | Description |
|-------|-----|-------------|
| [second-order-injection](./second-order-injection/) | CWE-89 | Data stored safely but used unsafely later |
| [encoding-bypass](./encoding-bypass/) | CWE-838 | Double-encoding and character set confusion |

### Advanced XSS Patterns

| Skill | CWE | Description |
|-------|-----|-------------|
| [mutation-xss](./mutation-xss/) | CWE-79 | Browser parsing mutations bypass sanitizers |
| [dom-clobbering](./dom-clobbering/) | CWE-79 | HTML injection overwrites DOM properties |

### Authentication Edge Cases

| Skill | CWE | Description |
|-------|-----|-------------|
| [timing-attacks](./timing-attacks/) | CWE-208 | Side-channel through timing differences |
| [oauth-security](./oauth-security/) | CWE-352 | Missing state parameter and PKCE |

### Cryptographic Edge Cases

| Skill | CWE | Description |
|-------|-----|-------------|
| [padding-oracle](./padding-oracle/) | CWE-649 | Error messages reveal padding validity |
| [length-extension-attacks](./length-extension-attacks/) | CWE-328 | hash(secret+msg) allows forgery |

### Input Validation Edge Cases

| Skill | CWE | Description |
|-------|-----|-------------|
| [redos](./redos/) | CWE-1333 | Regex catastrophic backtracking |
| [unicode-security](./unicode-security/) | CWE-176 | Confusables and normalization issues |
| [type-confusion](./type-confusion/) | CWE-843 | Weak typing and coercion exploits |
| [integer-overflow](./integer-overflow/) | CWE-190 | Arithmetic overflow bypasses validation |

## Usage

Include the relevant skill when:
- Generating code that handles user input
- Reviewing AI-generated code for security issues
- Building authentication, authorization, or session management
- Working with databases, file systems, or external commands
- Implementing APIs or web endpoints

## Related Skills

These anti-patterns complement the positive security patterns in [../security-patterns/](../security-patterns/):

| Anti-Pattern | Related Positive Pattern |
|--------------|-------------------------|
| sql-injection | data-validation |
| xss | output-filter |
| missing-authentication | authentication |
| hardcoded-secrets | cryptographic-key-management |
| weak-encryption | encryption |
| session-fixation | session-based-access-control |

## References

- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context) by Arcanum Security
- [CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/)
- [OWASP Top 10](https://owasp.org/Top10/)
