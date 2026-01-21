---
name: weak-password-hashing-anti-pattern
description: Security anti-pattern for weak password hashing (CWE-327, CWE-759). Use when generating or reviewing code that stores or verifies user passwords. Detects use of MD5, SHA1, SHA256 without salt, or missing password hashing entirely. Recommends bcrypt, Argon2, or scrypt.
---

# Weak Password Hashing Anti-Pattern

**Severity:** High

## Risk

AI models frequently suggest outdated password hashing (MD5, SHA-1, plain SHA-256) learned from legacy code in training data. Weak password hashing leads to:

- Mass password compromise via rainbow tables
- Fast brute-force cracking
- Credential stuffing across services
- Database breach escalation

A 14% failure rate for CWE-327 was documented in AI-generated code.

## BAD Pattern: MD5 or SHA1 for Passwords

```pseudocode
// VULNERABLE: Deprecated hash algorithms

FUNCTION hash_password_weak(password):
    // MD5 is cryptographically broken
    RETURN md5(password)
END FUNCTION

FUNCTION hash_password_sha1(password):
    // SHA-1 has known collision attacks
    RETURN sha1(password)
END FUNCTION

// Problems:
// - MD5: Collisions found in seconds, rainbow tables widely available
// - SHA-1: Collision attacks demonstrated (SHAttered, 2017)
// - Both: Too fast - billions of hashes per second on GPU
```

## BAD Pattern: Plain SHA-256 Without Salt

```pseudocode
// VULNERABLE: SHA-256 without proper password hashing

FUNCTION hash_password_unsalted(password):
    // Still vulnerable: No salt, too fast
    RETURN sha256(password)
END FUNCTION

FUNCTION hash_password_static_salt(password):
    // Vulnerable: Same salt for all users
    STATIC_SALT = "my_application_salt"
    RETURN sha256(STATIC_SALT + password)
END FUNCTION

// Problems:
// - No salt: Identical passwords have identical hashes
// - Static salt: Rainbow tables can be precomputed for your app
// - Fast hash: GPUs can try billions per second
```

## GOOD Pattern: bcrypt/Argon2/scrypt

```pseudocode
// SECURE: Modern password hashing algorithms

FUNCTION hash_password_secure(password):
    // Use bcrypt with cost factor
    salt = bcrypt.generate_salt(rounds=12)  // Adjustable work factor
    RETURN bcrypt.hash(password, salt)
END FUNCTION

FUNCTION verify_password_secure(password, stored_hash):
    // bcrypt handles salt extraction and timing-safe comparison
    RETURN bcrypt.verify(password, stored_hash)
END FUNCTION

// Alternative: Argon2id (recommended for new applications)
FUNCTION hash_password_argon2(password):
    RETURN argon2id.hash(password, {
        memory_cost: 65536,    // 64 MB
        time_cost: 3,          // 3 iterations
        parallelism: 4         // 4 threads
    })
END FUNCTION
```

## Algorithm Comparison

| Algorithm | Status | Speed | Use For |
|-----------|--------|-------|---------|
| MD5 | Broken | Very fast | Never for passwords |
| SHA-1 | Broken | Very fast | Never for passwords |
| SHA-256 | Secure* | Very fast | NOT for passwords |
| bcrypt | Secure | Intentionally slow | Passwords |
| Argon2id | Secure | Intentionally slow | Passwords (preferred) |
| scrypt | Secure | Intentionally slow | Passwords |

*SHA-256 is secure for integrity checks, NOT for password hashing due to speed.

## Cost Factor Guidelines

```pseudocode
// Choose cost factor based on acceptable login delay

// bcrypt rounds (target ~250ms on your hardware)
FUNCTION get_bcrypt_rounds():
    // 10 = ~100ms, 12 = ~400ms, 14 = ~1.5s
    RETURN 12  // Reasonable default
END FUNCTION

// Argon2 parameters (target ~250ms, ~64MB memory)
FUNCTION get_argon2_params():
    RETURN {
        memory_cost: 65536,  // 64 MB
        time_cost: 3,
        parallelism: 4
    }
END FUNCTION

// Adjust based on server capacity and user experience
```

## Detection

- Search for `md5(`, `sha1(`, `sha256(` in password-related code
- Look for password storage without bcrypt, argon2, or scrypt
- Check for static or missing salt values
- Review password verification for timing-safe comparison

## Prevention Checklist

- [ ] Use bcrypt, Argon2id, or scrypt for all password hashing
- [ ] Never use MD5, SHA-1, or plain SHA-256 for passwords
- [ ] Use library-provided salt generation (don't create your own)
- [ ] Set appropriate cost factors (bcrypt rounds, Argon2 memory)
- [ ] Use timing-safe comparison for password verification
- [ ] Consider Argon2id for new applications (current best practice)

## Related Patterns

- [hardcoded-secrets](../hardcoded-secrets/) - Don't hardcode password hashes
- [missing-authentication](../missing-authentication/) - Proper auth implementation
- [weak-encryption](../weak-encryption/) - Related cryptographic issues

## References

- [OWASP Top 10 A04:2025 - Cryptographic Failures](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/)
- [OWASP API Security API2:2023 - Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [CWE-327: Broken Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [CAPEC-55: Rainbow Table Password Cracking](https://capec.mitre.org/data/definitions/55.html)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
