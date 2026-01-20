---
name: length-extension-attacks-anti-pattern
description: Security anti-pattern for hash length extension vulnerabilities (CWE-328). Use when generating or reviewing code that uses hash(secret + message) for authentication, API signatures, or integrity verification. Detects Merkle-Damgard hash misuse.
---

# Length Extension Attacks Anti-Pattern

**Severity:** High

## Risk

Length extension attacks exploit Merkle-Damgard hash constructions (MD5, SHA-1, SHA-256) where knowing `hash(secret + message)` and the length of `secret` allows computing `hash(secret + message + padding + attacker_data)` without knowing the secret. This leads to:

- Authentication token forgery
- API signature bypass
- Parameter tampering
- Integrity check bypass

## How Length Extension Works

```pseudocode
// The vulnerability:
// Given: hash(secret + message) and length(secret)
// Attacker can compute: hash(secret + message + padding + anything)
// Without knowing the secret!

// Example attack scenario:
// Original: hash(secret + "amount=100") = abc123...
// Server verifies: compute hash(secret + params), compare to provided hash

// Attacker:
// 1. Knows hash value: abc123...
// 2. Knows message: "amount=100"
// 3. Guesses secret length (try 8, 16, 32 bytes)
// 4. Computes: hash(secret + "amount=100" + padding + "&amount=999")
// 5. Server computes same hash (secret included), verification passes!
// 6. Server processes amount=999 (last parameter wins)
```

## BAD Pattern: hash(secret + message)

```pseudocode
// VULNERABLE: Using hash(secret + message) for authentication

FUNCTION create_auth_token(secret_key, message):
    RETURN sha256(secret_key + message)  // Length extension vulnerable!
END FUNCTION

FUNCTION verify_auth_token(secret_key, message, token):
    expected = sha256(secret_key + message)
    RETURN token == expected
END FUNCTION

// Attack example:
// User requests: /api?user=alice&role=user
// Server creates: token = sha256(secret + "user=alice&role=user")

// Attacker extends: hash(secret + "user=alice&role=user" + padding + "&role=admin")
// Sends: /api?user=alice&role=user[padding]&role=admin
// With forged token that validates!
```

## BAD Pattern: API Request Signing

```pseudocode
// VULNERABLE: API signature using hash(key + params)

FUNCTION sign_request(api_key, params):
    param_string = sort_and_join(params)
    signature = sha256(api_key + param_string)
    RETURN signature
END FUNCTION

FUNCTION verify_request(api_key, params, signature):
    expected = sha256(api_key + param_string(params))
    RETURN signature == expected  // Vulnerable to extension!
END FUNCTION

// Attacker can append parameters to signed request
```

## GOOD Pattern: Use HMAC

```pseudocode
// SECURE: HMAC prevents length extension

FUNCTION create_auth_token_secure(secret_key, message):
    RETURN HMAC_SHA256(secret_key, message)
END FUNCTION

FUNCTION verify_auth_token_secure(secret_key, message, token):
    expected = HMAC_SHA256(secret_key, message)
    RETURN constant_time_equals(token, expected)
END FUNCTION

// HMAC construction: hash(key XOR opad || hash(key XOR ipad || message))
// This structure prevents length extension attacks
```

## GOOD Pattern: hash(message + secret)

```pseudocode
// ACCEPTABLE: Reversing order prevents extension
// (But HMAC is still recommended)

FUNCTION create_token_reversed(secret_key, message):
    // Attacker cannot extend because secret is at the end
    RETURN sha256(message + secret_key)
END FUNCTION

// Note: This is NOT as robust as HMAC
// Still vulnerable to other attacks in some scenarios
// Always prefer HMAC
```

## GOOD Pattern: Use SHA-3

```pseudocode
// SECURE: SHA-3 is resistant to length extension

FUNCTION create_token_sha3(secret_key, message):
    // SHA-3 uses sponge construction, not Merkle-Damgard
    // Inherently resistant to length extension
    RETURN SHA3_256(secret_key + message)
END FUNCTION

// Still, HMAC is the standard for keyed authentication
// Use HMAC for consistency across algorithms
```

## Vulnerable vs Resistant Algorithms

| Algorithm | Vulnerable | Notes |
|-----------|------------|-------|
| MD5 | Yes | Merkle-Damgard |
| SHA-1 | Yes | Merkle-Damgard |
| SHA-256 | Yes | Merkle-Damgard |
| SHA-512 | Yes | Merkle-Damgard |
| SHA-3 | No | Sponge construction |
| BLAKE2 | No | Different construction |
| HMAC-* | No | Designed to prevent this |

## Detection

- Search for `hash(secret + message)` or `hash(key + data)` patterns
- Look for SHA-256/SHA-1/MD5 used directly with secret prefix
- Check API signature implementations
- Review authentication token generation
- Look for integrity checks using simple hashing

## Prevention Checklist

- [ ] Use HMAC for all keyed authentication
- [ ] Never use hash(secret + message) construction
- [ ] Use constant-time comparison for verification
- [ ] If using SHA-3, still prefer HMAC for consistency
- [ ] Document which hash constructions are used where
- [ ] Audit legacy code for vulnerable patterns

## Related Patterns

- [weak-encryption](../weak-encryption/) - Related crypto issues
- [timing-attacks](../timing-attacks/) - Comparison timing
- [insufficient-randomness](../insufficient-randomness/) - Secret generation

## References

- [OWASP Top 10 A02:2021 - Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [CWE-328: Reversible One-Way Hash](https://cwe.mitre.org/data/definitions/328.html)
- [CAPEC-97: Cryptanalysis](https://capec.mitre.org/data/definitions/97.html)
- [Length Extension Attack (Wikipedia)](https://en.wikipedia.org/wiki/Length_extension_attack)
- [Hash Length Extension Attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
