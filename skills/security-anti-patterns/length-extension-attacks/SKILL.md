---
name: "length-extension-attacks-anti-pattern"
description: "Security anti-pattern for hash length extension vulnerabilities (CWE-328). Use when generating or reviewing code that uses hash(secret + message) for authentication, API signatures, or integrity verification. Detects Merkle-Damgard hash misuse."
---

# Length Extension Attacks Anti-Pattern

**Severity:** High

## Summary

A hash length extension attack is a cryptographic vulnerability that affects certain hash functions, including MD5, SHA-1, and SHA-256. The vulnerability stems from their internal structure (the Merkle-Damgård construction). If an attacker knows the hash of `secret + message` and the length of the `secret`, they can calculate the hash of `secret + message + padding + attacker_data` *without knowing the secret itself*. This allows them to append data to a signed message and generate a valid new signature, completely breaking the integrity and authentication of the message.

## The Anti-Pattern

The anti-pattern is using a vulnerable hash function (like SHA-256) in the construction `hash(secret + message)` to create a message authentication code (MAC).

### BAD Code Example

```python
# VULNERABLE: Using hash(secret + message) for a message signature.
import hashlib

SECRET_KEY = b"my_super_secret_key_16b" # 16 bytes long

def get_signed_url(message):
    # The signature is created by prepending the secret to the message and hashing.
    # This is vulnerable to length extension.
    signature = hashlib.sha256(SECRET_KEY + message.encode()).hexdigest()
    return f"/api/action?{message}&signature={signature}"

def verify_request(message, signature):
    expected_signature = hashlib.sha256(SECRET_KEY + message.encode()).hexdigest()
    return signature == expected_signature

# 1. A legitimate URL is generated:
#    Message: "user=alice&action=view"
#    URL: /api/action?user=alice&action=view&signature=...

# 2. An attacker intercepts this URL. They know the signature and the message.
#    They don't know the SECRET_KEY, but they can guess its length (16 bytes).

# 3. Using a tool like `hashpump`, the attacker can compute a new, valid signature for an extended message.
#    Original Message: "user=alice&action=view"
#    Extended Message: "user=alice&action=view" + padding + "&action=delete&target=bob"
#    The tool generates a new signature and the new message string including the padding.

# 4. The server receives the forged request, recomputes the hash of `SECRET_KEY + extended_message`,
#    and finds that it matches the attacker's new signature. The delete action is processed.
```

### GOOD Code Example

```python
# SECURE: Use HMAC (Hash-based Message Authentication Code).
import hmac
import hashlib

SECRET_KEY = b"my_super_secret_key_16b"

def get_signed_url_secure(message):
    # HMAC is specifically designed to prevent length extension attacks.
    # It uses a two-step hashing process: hash(key XOR opad, hash(key XOR ipad, message))
    signature = hmac.new(SECRET_KEY, message.encode(), hashlib.sha256).hexdigest()
    return f"/api/action?{message}&signature={signature}"

def verify_request_secure(message, signature):
    expected_signature = hmac.new(SECRET_KEY, message.encode(), hashlib.sha256).hexdigest()
    # Use hmac.compare_digest for constant-time comparison to prevent timing attacks.
    return hmac.compare_digest(signature, expected_signature)

# An attacker cannot extend an HMAC-signed message because they don't know the secret key.
# The inner hash `hash(key XOR ipad, message)` prevents them from being able
# to continue the hash chain.
```

## Detection

- **Review code:** Look for any instance where a message signature or MAC is created by concatenating a secret *at the beginning* of a message and then hashing it with MD5, SHA-1, or SHA-256. The pattern is `hash(secret + data)`.
- **Check for vulnerable hash functions:** Identify which hash algorithms are being used. If you see MD5, SHA-1, or SHA-2 (SHA-224, SHA-256, SHA-384, SHA-512) used for signing, check the construction.
- **Use cryptographic analysis tools:** Some advanced static analysis tools can identify weak cryptographic constructions.

## Prevention

- [ ] **Use HMAC:** Always use HMAC for creating message authentication codes. HMAC is the industry standard and is implemented in the standard library of most modern languages. It is specifically designed to be immune to length extension attacks.
- [ ] **Choose a secure hash function:** Use HMAC with a strong hash function like SHA-256 or SHA-3.
- [ ] **Do not roll your own cryptography:** Avoid creating custom signing schemes like `hash(message + secret)` or `hash(secret + message + secret)`. While some might be safe from this specific attack, they may have other flaws. Stick to the standard: HMAC.
- [ ] **If you cannot use HMAC**, use a hash function that is not vulnerable to length extension, such as SHA-3 or BLAKE2. However, HMAC is still the preferred and most widely supported solution.

## Related Security Patterns & Anti-Patterns

- [Weak Encryption Anti-Pattern](../weak-encryption/): Part of the broader category of cryptographic failures.
- [Timing Attacks Anti-Pattern](../timing-attacks/): When verifying signatures, it's important to use a constant-time comparison function to avoid leaking information through timing differences.

## References

- [OWASP Top 10 A04:2025 - Cryptographic Failures](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/)
- [OWASP GenAI LLM10:2025 - Unbounded Consumption](https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/)
- [CWE-328: Reversible One-Way Hash](https://cwe.mitre.org/data/definitions/328.html)
- [CAPEC-97: Cryptanalysis](https://capec.mitre.org/data/definitions/97.html)
- [Length Extension Attack (Wikipedia)](https://en.wikipedia.org/wiki/Length_extension_attack)
- [Hash Length Extension Attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
