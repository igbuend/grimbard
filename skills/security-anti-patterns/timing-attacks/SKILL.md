---
name: "timing-attacks-anti-pattern"
description: "Security anti-pattern for timing side-channel vulnerabilities (CWE-208). Use when generating or reviewing code that compares secrets, tokens, passwords, or cryptographic values. Detects early-exit comparisons that leak information through timing differences."
---

# Timing Attacks Anti-Pattern

**Severity:** Medium

## Summary
A timing attack is a side-channel attack where an attacker observes the time it takes for a cryptographic operation or a secret comparison to complete. If an application's code for comparing a secret (like a password or an API key) stops as soon as it finds a mismatch, it leaks information. For example, comparing `ABCDEF` to `ABCDEG` will take slightly longer than comparing `ABCDEF` to `XBCDEF` because more characters are compared before a mismatch is found. An attacker can use these minute timing differences to guess the secret character by character, eventually recovering the entire secret.

## The Anti-Pattern
The anti-pattern is using a comparison function that returns early upon finding a difference when comparing two sensitive values (e.g., passwords, tokens, cryptographic hashes).

### BAD Code Example
```python
# VULNERABLE: Naive string comparison that leaks timing information.
import time

def insecure_compare(s1, s2):
    # This comparison function exits as soon as a mismatch is found.
    # If s1 and s2 differ at the first character, it returns quickly.
    # If they differ at the last character, it takes longer.
    if len(s1) != len(s2):
        return False
    for i in range(len(s1)):
        if s1[i] != s2[i]:
            return False # Early exit.
        # Adding a small, consistent delay here might make the timing difference more apparent
        # for an attacker, but doesn't fix the fundamental flaw.
        # time.sleep(0.000001)
    return True

SECRET_TOKEN = "abcdef123456" # This is the secret the attacker wants to guess.

@app.route("/check_token")
def check_token():
    provided_token = request.args.get("token")
    if insecure_compare(provided_token, SECRET_TOKEN):
        return "Token valid!"
    return "Token invalid!"

# Attacker's strategy:
# 1. Guess the first character: 'a', 'b', 'c', etc.
#    - Request `/check_token?token=X` -> very fast response.
#    - Request `/check_token?token=a` -> slightly slower response (first char matches).
# 2. Once 'a' is confirmed, guess the second: 'ab', 'ac', etc.
#    - Request `/check_token?token=aX` -> slightly slower than 'X'.
#    - Request `/check_token?token=ab` -> even slower (first two chars match).
# This allows the attacker to discover the secret character by character.
```

### GOOD Code Example
```python
# SECURE: Use a constant-time comparison function that always takes the same amount of time.
import hmac # Python's `hmac` module provides `compare_digest` for constant-time comparison.
import secrets # For securely generating random tokens

def secure_compare(s1_bytes, s2_bytes):
    # `hmac.compare_digest` compares two byte strings in a "constant-time" manner.
    # It ensures that the execution time does not depend on the values of the strings,
    # only on their length. It performs a full comparison of both strings.
    return hmac.compare_digest(s1_bytes, s2_bytes)

SECRET_TOKEN = secrets.token_bytes(16) # A truly random, 16-byte (128-bit) secret.

@app.route("/check_token_secure")
def check_token_secure():
    provided_token_hex = request.args.get("token")
    try:
        provided_token_bytes = bytes.fromhex(provided_token_hex)
    except ValueError:
        return "Token invalid!", 400

    # Ensure the length of the provided token is the same as the secret.
    # If lengths differ, `hmac.compare_digest` handles it safely, returning False.
    if len(provided_token_bytes) != len(SECRET_TOKEN):
        return "Token invalid!", 400

    if secure_compare(provided_token_bytes, SECRET_TOKEN):
        return "Token valid!"
    return "Token invalid!"
```

## Detection
- **Review code for secret comparisons:** Look for any place in the code where sensitive values (passwords, API keys, session tokens, cryptographic hashes, HMAC signatures) are compared.
- **Identify standard equality operators:** Search for `==` or `===` being used for comparing secrets. These operators are typically not constant-time.
- **Look for custom comparison loops:** If a custom loop iterates through characters and returns `False` on the first mismatch, it's vulnerable.

## Prevention
- [ ] **Always use a constant-time comparison function** when comparing secrets or other security-sensitive values.
- [ ] **Know your language's constant-time comparison functions:**
    - **Python:** `hmac.compare_digest()` or `secrets.compare_digest()`.
    - **Node.js:** `crypto.timingSafeEqual()`.
    - **Go:** `subtle.ConstantTimeCompare()`.
    - **Java:** `MessageDigest.isEqual()` (for byte arrays).
    - **PHP:** `hash_equals()`.
- [ ] **For password hashing verification:** Always use the library's provided verification function (e.g., `bcrypt.checkpw()` or `argon2.verify()`), as these are designed to be timing-safe.
- [ ] **Ensure the lengths of the values being compared are the same.** If they are not, `hmac.compare_digest` and similar functions will typically return `False` in a constant-time manner.

## Related Security Patterns & Anti-Patterns
- [Weak Password Hashing Anti-Pattern](../weak-password-hashing/): Proper password hashing (e.g., bcrypt) includes protection against timing attacks during verification.
- [JWT Misuse Anti-Pattern](../jwt-misuse/): Signature verification of JWTs should use constant-time comparisons.
- [Padding Oracle Anti-Pattern](../padding-oracle/): Another type of cryptographic timing issue where information about padding validity is leaked through timing.

## References
- [OWASP Top 10 A04:2025 - Cryptographic Failures](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/)
- [OWASP GenAI LLM10:2025 - Unbounded Consumption](https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/)
- [OWASP API Security API2:2023 - Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)
- [OWASP Testing for Timing Attacks](https://owasp.org/www-project-web-security-testing-guide/)
- [CWE-208: Observable Timing Discrepancy](https://cwe.mitre.org/data/definitions/208.html)
- [CAPEC-462: Cross-Domain Search Timing](https://capec.mitre.org/data/definitions/462.html)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
