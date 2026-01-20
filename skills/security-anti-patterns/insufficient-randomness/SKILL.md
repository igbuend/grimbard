---
name: insufficient-randomness-anti-pattern
description: Security anti-pattern for insufficient randomness vulnerabilities (CWE-330). Use when generating or reviewing code that creates security tokens, session IDs, encryption keys, nonces, or any security-critical random values. Detects use of Math.random() or predictable seeds.
---

# Insufficient Randomness Anti-Pattern

**Severity:** High

## Risk

Using non-cryptographic random number generators for security purposes makes values predictable. Attackers can:

- Predict session IDs and hijack sessions
- Forge authentication tokens
- Recover encryption keys
- Bypass security controls

AI models often suggest `Math.random()` or `random.random()` for security tokens because these appear frequently in tutorials.

## BAD Pattern: Math.random() for Security

```pseudocode
// VULNERABLE: Math.random() / random.random() is predictable

FUNCTION generate_session_id_weak():
    // Vulnerable: Uses predictable PRNG (Mersenne Twister)
    RETURN random.randint(0, 999999999)
END FUNCTION

FUNCTION generate_token_weak():
    // Vulnerable: Using random module for security tokens
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    token = ""
    FOR i = 0 TO 32:
        token += chars[random.randint(0, chars.length - 1)]
    END FOR
    RETURN token
END FUNCTION

// Problems:
// - Math.random(): Uses predictable PRNG
// - Internal state: Can be recovered from ~624 outputs
// - Attacker can predict next values after observing enough outputs
```

## GOOD Pattern: Cryptographically Secure Random

```pseudocode
// SECURE: Use cryptographically secure randomness

FUNCTION generate_session_id_secure():
    // Use secrets module (Python) or crypto.randomBytes (Node)
    RETURN secrets.token_urlsafe(32)  // 256 bits of entropy
END FUNCTION

FUNCTION generate_token_secure():
    // cryptographically secure hex token
    RETURN secrets.token_hex(32)  // 256 bits as hex string
END FUNCTION

FUNCTION generate_key_secure():
    // Use OS entropy source
    RETURN os.urandom(32)  // 256 bits from /dev/urandom
END FUNCTION
```

## BAD Pattern: Time-Based Seeding

```pseudocode
// VULNERABLE: Time-based seeding is predictable

FUNCTION generate_key_weak():
    // Attacker can guess seed from approximate time
    random.seed(current_timestamp())
    key = random.randbytes(32)
    RETURN key
END FUNCTION

FUNCTION generate_reset_token_weak():
    // Vulnerable: Based on timestamp
    seed = current_time_milliseconds()
    random.seed(seed)
    RETURN random.randint(100000, 999999)
END FUNCTION
```

## GOOD Pattern: OS Entropy

```pseudocode
// SECURE: Use OS-provided entropy

FUNCTION generate_key_secure():
    // No seeding needed - uses hardware entropy
    RETURN crypto.secure_random_bytes(32)
END FUNCTION

FUNCTION generate_reset_token_secure():
    // Cryptographically random 6-digit code
    RETURN secrets.randbelow(900000) + 100000
END FUNCTION
```

## Language-Specific Secure Random APIs

| Language | Secure | Insecure |
|----------|--------|----------|
| Python | `secrets`, `os.urandom()` | `random` |
| JavaScript | `crypto.randomBytes()`, `crypto.getRandomValues()` | `Math.random()` |
| Java | `SecureRandom` | `Random`, `Math.random()` |
| Go | `crypto/rand` | `math/rand` |
| C# | `RandomNumberGenerator` | `Random` |
| Ruby | `SecureRandom` | `rand()` |

## Detection

- Search for `Math.random()`, `random.random()`, `random.randint()` in security contexts
- Look for `random.seed()` with time-based values
- Check if `Random` class is used instead of `SecureRandom`
- Review token generation, session ID creation, and key generation code

## Prevention Checklist

- [ ] Use cryptographically secure random for all security tokens
- [ ] Never use `Math.random()` or language `random` module for security
- [ ] Generate at least 128 bits (16 bytes) of randomness for tokens
- [ ] Use 256 bits for encryption keys
- [ ] Don't seed RNG with time - use OS entropy
- [ ] Verify your random source draws from OS entropy pool

## Related Patterns

- [session-fixation](../session-fixation/) - Session ID generation
- [hardcoded-secrets](../hardcoded-secrets/) - Key management
- [weak-encryption](../weak-encryption/) - Encryption key requirements

## References

- [OWASP Top 10 A02:2021 - Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [CWE-330: Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
- [CAPEC-112: Brute Force](https://capec.mitre.org/data/definitions/112.html)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
