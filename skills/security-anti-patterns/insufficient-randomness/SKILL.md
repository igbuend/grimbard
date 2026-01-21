---
name: "insufficient-randomness-anti-pattern"
description: "Security anti-pattern for insufficient randomness vulnerabilities (CWE-330). Use when generating or reviewing code that creates security tokens, session IDs, encryption keys, nonces, or any security-critical random values. Detects use of Math.random() or predictable seeds."
---

# Insufficient Randomness Anti-Pattern

**Severity:** High

## Summary

Insufficient randomness is a critical vulnerability that occurs when a security-sensitive value, such as a session token, password reset code, or encryption key, is generated using a predictable or non-cryptographically secure random number generator (PRNG). AI models often suggest using standard PRNGs like `Math.random()` or Python's `random` module because they are simple and common in general-purpose programming. However, these generators are not designed for security. Their output can be predicted by an attacker who observes a few values, allowing them to forge tokens, hijack sessions, or compromise cryptographic operations.

## The Anti-Pattern

The anti-pattern is using a predictable, non-cryptographic random number generator for any value that needs to be unpredictable for security reasons.

### BAD Code Example

```javascript
// VULNERABLE: Using Math.random() to generate a session token.

function generateSessionToken() {
    let token = '';
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    // Math.random() is a standard PRNG, not a cryptographically secure one.
    // Its output is predictable if an attacker can observe enough previous values
    // or has some knowledge of the initial seed (which can be time-based).
    for (let i = 0; i < 32; i++) {
        token += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return token;
}

// An attacker who obtains a few of these tokens can potentially
// reverse-engineer the PRNG's internal state and predict future tokens.
```

### GOOD Code Example

```javascript
// SECURE: Using a cryptographically secure pseudo-random number generator (CSPRNG).
const crypto = require('crypto');

function generateSessionToken() {
    // `crypto.randomBytes()` generates random data using the operating system's
    // underlying entropy sources, making it unpredictable.
    // It is designed specifically for cryptographic use cases.
    const buffer = crypto.randomBytes(32); // Generate 32 bytes of random data.
    return buffer.toString('hex'); // Convert to a hex string for easy use.
}

// The resulting token is 64 characters long and has 256 bits of entropy,
// making it infeasible for an attacker to guess or predict.
```

## Detection

- **Search the codebase** for the use of non-cryptographic random functions in security-sensitive contexts. Look for:
  - `Math.random()` in JavaScript.
  - The `random` module in Python.
  - The `java.util.Random` class in Java.
  - `rand()` in PHP or C.
- **Review seeding:** Look for any manual seeding of a random number generator, especially using a predictable value like the current time (`random.seed(time.time())`). CSPRNGs do not need to be manually seeded.
- **Check token generation logic:** Examine how session IDs, password reset tokens, API keys, and other secrets are created.

## Prevention

- [ ] **Always use a cryptographically secure pseudo-random number generator (CSPRNG)** for any security-related value.
- [ ] **Know your language's CSPRNG:**
  - **Python:** Use the `secrets` module or `os.urandom()`.
  - **JavaScript (Node.js):** Use `crypto.randomBytes()` or `crypto.getRandomValues()`.
  - **Java:** Use `java.security.SecureRandom`.
  - **Go:** Use the `crypto/rand` package.
  - **C#:** Use `System.Security.Cryptography.RandomNumberGenerator`.
- [ ] **Ensure sufficient entropy:** Generate at least 128 bits (16 bytes) of randomness for tokens and unique identifiers. Use 256 bits (32 bytes) for encryption keys.
- [ ] **Never seed a CSPRNG manually.** They are designed to automatically draw entropy from the operating system.

## Related Security Patterns & Anti-Patterns

- [Session Fixation Anti-Pattern](../session-fixation/): Secure session ID generation is a key defense against session fixation.
- [Hardcoded Secrets Anti-Pattern](../hardcoded-secrets/): If an encryption key is generated with insufficient randomness, it's as bad as hardcoding a weak key.
- [Weak Encryption Anti-Pattern](../weak-encryption/): The security of an encryption algorithm relies on the unpredictability of its key.

## References

- [OWASP Top 10 A04:2025 - Cryptographic Failures](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/)
- [OWASP GenAI LLM06:2025 - Excessive Agency](https://genai.owasp.org/llmrisk/llm06-excessive-agency/)
- [OWASP API Security API2:2023 - Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)
- [CWE-330: Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
- [CAPEC-112: Brute Force](https://capec.mitre.org/data/definitions/112.html)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
