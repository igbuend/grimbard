---
name: "encoding-bypass-anti-pattern"
description: "Security anti-pattern for encoding bypass vulnerabilities (CWE-838). Use when generating or reviewing code that handles URL encoding, Unicode normalization, or character set conversions before security validation. Detects validation before normalization and double-encoding issues."
---

# Encoding Bypass Anti-Pattern

**Severity:** High

## Summary

Encoding bypass vulnerabilities occur when an application's security checks can be evaded by using alternate or multiple encodings for malicious input. This anti-pattern typically happens when data is validated *before* it is fully decoded or normalized. An attacker can submit a payload that appears safe in its encoded form but becomes malicious after the application processes it. This can lead to the bypass of web application firewalls (WAFs), input filters, and other security mechanisms, enabling attacks like XSS and SQL Injection.

## The Anti-Pattern

The core of this anti-pattern is a flawed order of operations: **Validate then Decode/Normalize**. Security checks are performed on encoded or non-canonical data, and the application later uses a decoded or normalized version of that same data, re-introducing the vulnerability.

### BAD Code Example

```python
# VULNERABLE: Validation happens before Unicode normalization.
import unicodedata

def is_safe_username(username):
    # This check is flawed because it doesn't account for Unicode variants.
    if '<' in username or '>' in username:
        return False
    return True

def create_user_profile(username):
    if not is_safe_username(username):
        raise ValueError("Invalid characters in username.")

    # The application later normalizes the username for display or storage.
    # The full-width less-than sign '＜' (U+FF1C) was not caught by the check.
    # It gets normalized into the standard '<' (U+003C), enabling XSS.
    normalized_username = unicodedata.normalize('NFKC', username)

    # This will render the malicious script tag.
    return f"<div>Welcome, {normalized_username}</div>"

# Attacker's input: '＜script＞alert(1)＜/script＞'
# is_safe_username returns True.
# The normalized output becomes '<div>Welcome, <script>alert(1)</script></div>'
```

### GOOD Code Example

```python
# SECURE: Normalize then validate.
import unicodedata

def is_safe_username(username):
    # This check is now effective because it runs on the canonical form of the input.
    if '<' in username or '>' in username:
        return False
    return True

def create_user_profile(username):
    # First, normalize the input to its canonical form.
    normalized_username = unicodedata.normalize('NFKC', username)

    # Then, perform the security validation on the normalized data.
    if not is_safe_username(normalized_username):
        raise ValueError("Invalid characters in username.")

    # Now it's safe to use the normalized username.
    return f"<div>Welcome, {normalized_username}</div>"
```

## Detection

- **Review the order of operations:** Check if security validation (e.g., checking for bad characters, path traversal patterns) occurs before or after decoding (e.g., URL decoding, Base64 decoding) and normalization (e.g., Unicode normalization).
- **Test with multiple encodings:** Send payloads with various encodings to see if they bypass filters. Common techniques include:
  - **URL encoding:** `%3c` for `<`
  - **Double URL encoding:** `%253c` for `<`
  - **Unicode escape sequences:** `\u003c` for `<`
  - **HTML entities:** `&#60;` for `<`
  - **Full-width and other Unicode variants:** `＜` (U+FF1C) for `<`
- Look for places where data is decoded more than once in the request pipeline.

## Prevention

- [ ] **Normalize/decode before validation:** Always bring data to its simplest, canonical form before performing any security checks on it.
- [ ] **Use parameterized queries (for SQL)** and other safe APIs that handle encoding internally. This is the best defense against injection attacks.
- [ ] **Enforce strict character encoding** for all input (e.g., reject any data that is not valid UTF-8).
- [ ] **Be aware of implicit decoding** performed by your web framework or libraries and ensure your validation logic runs after it.
- [ ] **Canonicalize paths** and URLs before validating them to prevent path traversal attacks.

## Related Security Patterns & Anti-Patterns

- [SQL Injection Anti-Pattern](../sql-injection/): A common goal of encoding bypass attacks.
- [Cross-Site Scripting (XSS) Anti-Pattern](../xss/): Often enabled by bypassing filters with encoded payloads.
- [Path Traversal Anti-Pattern](../path-traversal/): Can be achieved by using encoded representations of `../`.
- [Unicode Security Anti-Pattern](../unicode-security/): A collection of issues related to handling Unicode securely.

## References

- [OWASP Top 10 A05:2025 - Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)
- [OWASP GenAI LLM05:2025 - Improper Output Handling](https://genai.owasp.org/llmrisk/llm05-improper-output-handling/)
- [OWASP API Security API8:2023 - Security Misconfiguration](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/)
- [OWASP Testing for HTTP Incoming Requests](https://owasp.org/www-project-web-security-testing-guide/)
- [CWE-838: Inappropriate Encoding for Output Context](https://cwe.mitre.org/data/definitions/838.html)
- [CAPEC-267: Leverage Alternate Encoding](https://capec.mitre.org/data/definitions/267.html)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
