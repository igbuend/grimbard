---
name: timing-attacks-anti-pattern
description: Security anti-pattern for timing side-channel vulnerabilities (CWE-208). Use when generating or reviewing code that compares secrets, tokens, passwords, or cryptographic values. Detects early-exit comparisons that leak information through timing differences.
---

# Timing Attacks Anti-Pattern

**Severity:** Medium

## Risk

Timing attacks exploit measurable time differences in operations to extract secret information. When comparing secrets, early-exit comparisons reveal how many characters matched before failure. This leads to:

- Token/password character-by-character extraction
- API key discovery
- HMAC bypass
- Authentication bypass through incremental guessing

## BAD Pattern: Early-Exit String Comparison

```pseudocode
// VULNERABLE: Early return reveals password length information

FUNCTION verify_password_vulnerable(input, stored):
    IF length(input) != length(stored):
        RETURN FALSE  // Fast return reveals length mismatch
    END IF

    FOR i = 0 TO length(input) - 1:
        IF input[i] != stored[i]:
            RETURN FALSE  // Fast return reveals first different character
        END IF
    END FOR

    RETURN TRUE
END FUNCTION

// Attack: Time difference reveals character position
// Wrong first char: ~10ms
// Wrong second char: ~11ms (one more comparison)
// Attacker guesses character by character
```

## BAD Pattern: Standard String Equality

```pseudocode
// VULNERABLE: Language's == operator may short-circuit

FUNCTION check_token_vulnerable(provided_token, expected_token):
    // == operator may return as soon as first difference found
    RETURN provided_token == expected_token
END FUNCTION

FUNCTION check_password_vulnerable(password, hash):
    computed_hash = sha256(password)
    RETURN computed_hash == hash  // Short-circuit comparison
END FUNCTION
```

## GOOD Pattern: Constant-Time Comparison

```pseudocode
// SECURE: Compare all bytes regardless of match

FUNCTION constant_time_equals(a, b):
    // Handle different lengths without revealing which is longer
    IF length(a) != length(b):
        // Pad shorter string to prevent length oracle
        b = b + repeat("\0", max(0, length(a) - length(b)))
        a = a + repeat("\0", max(0, length(b) - length(a)))
    END IF

    result = 0
    FOR i = 0 TO length(a) - 1:
        // XOR accumulates differences without early exit
        result = result OR (char_code(a[i]) XOR char_code(b[i]))
    END FOR

    RETURN result == 0
END FUNCTION
```

## GOOD Pattern: Use Library Functions

```pseudocode
// SECURE: Use library-provided constant-time comparison

FUNCTION verify_password_secure(password, hashed_password):
    // bcrypt.compare is designed to be constant-time
    RETURN bcrypt.compare(password, hashed_password)
END FUNCTION

FUNCTION verify_hash_secure(input, expected):
    input_hash = sha256(input)
    // Use crypto library's timing-safe comparison
    RETURN crypto.timing_safe_equal(
        Buffer.from(input_hash, 'hex'),
        Buffer.from(expected, 'hex')
    )
END FUNCTION

FUNCTION verify_token_secure(provided, expected):
    // Python: hmac.compare_digest()
    // Node.js: crypto.timingSafeEqual()
    // Go: subtle.ConstantTimeCompare()
    RETURN crypto.timing_safe_equal(provided, expected)
END FUNCTION
```

## GOOD Pattern: Constant-Time HMAC Verification

```pseudocode
// SECURE: HMAC verification with constant-time compare

FUNCTION verify_signature(message, signature, key):
    expected_sig = hmac_sha256(key, message)

    // CRITICAL: Use constant-time comparison
    RETURN crypto.timing_safe_equal(
        Buffer.from(signature, 'base64'),
        Buffer.from(expected_sig, 'base64')
    )
END FUNCTION
```

## Language-Specific Secure Functions

| Language | Constant-Time Function |
|----------|----------------------|
| Python | `hmac.compare_digest()`, `secrets.compare_digest()` |
| Node.js | `crypto.timingSafeEqual()` |
| Go | `subtle.ConstantTimeCompare()` |
| Java | `MessageDigest.isEqual()` |
| Ruby | `Rack::Utils.secure_compare()` |
| PHP | `hash_equals()` |

## Detection

- Look for `==` or `===` comparisons of secrets/tokens/hashes
- Search for custom comparison functions without constant-time logic
- Check password verification for use of bcrypt/argon2 compare functions
- Review HMAC verification for proper comparison methods
- Test with timing measurement tools

## Prevention Checklist

- [ ] Use language-provided constant-time comparison functions
- [ ] Use bcrypt.compare() or argon2.verify() for passwords
- [ ] Never use `==` to compare secrets, tokens, or hashes
- [ ] Ensure HMAC signatures use timing-safe comparison
- [ ] Add rate limiting as defense in depth
- [ ] Consider adding random delays (not as primary defense)

## Related Patterns

- [weak-password-hashing](../weak-password-hashing/) - bcrypt provides timing safety
- [jwt-misuse](../jwt-misuse/) - JWT signature verification timing
- [padding-oracle](../padding-oracle/) - Related crypto timing issue

## References

- [OWASP Top 10 A04:2025 - Cryptographic Failures](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/)
- [OWASP Testing for Timing Attacks](https://owasp.org/www-project-web-security-testing-guide/)
- [CWE-208: Observable Timing Discrepancy](https://cwe.mitre.org/data/definitions/208.html)
- [CAPEC-462: Cross-Domain Search Timing](https://capec.mitre.org/data/definitions/462.html)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
