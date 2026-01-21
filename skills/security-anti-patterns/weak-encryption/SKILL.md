---
name: weak-encryption-anti-pattern
description: Security anti-pattern for weak encryption (CWE-326, CWE-327). Use when generating or reviewing code that encrypts data, handles encryption keys, or uses cryptographic modes. Detects DES, ECB mode, static IVs, and custom crypto implementations.
---

# Weak Encryption Anti-Pattern

**Severity:** High

## Risk

AI models frequently suggest outdated encryption algorithms and modes learned from legacy code. Weak encryption leads to:

- Data exposure through decryption
- Pattern leakage revealing plaintext structure
- Authentication bypass
- Compliance failures

A "significant increase" in encryption vulnerabilities was documented when using AI assistants.

## BAD Pattern: DES or 3DES

```pseudocode
// VULNERABLE: DES uses 56-bit keys (trivially breakable)

FUNCTION encrypt_data_weak(plaintext, key):
    cipher = DES.new(key, mode=ECB)
    RETURN cipher.encrypt(plaintext)
END FUNCTION

// Problems:
// - DES: Brute-forceable in hours with modern hardware
// - 3DES: Deprecated, vulnerable to Sweet32 attack
```

## GOOD Pattern: AES-256-GCM

```pseudocode
// SECURE: Modern authenticated encryption

FUNCTION encrypt_data_secure(plaintext, key):
    // Use AES-256-GCM or ChaCha20-Poly1305
    nonce = crypto.secure_random_bytes(12)
    cipher = AES_GCM.new(key, nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    RETURN nonce + tag + ciphertext  // Include nonce and auth tag
END FUNCTION

FUNCTION decrypt_data_secure(encrypted_data, key):
    nonce = encrypted_data[0:12]
    tag = encrypted_data[12:28]
    ciphertext = encrypted_data[28:]

    cipher = AES_GCM.new(key, nonce)
    TRY:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        RETURN plaintext
    CATCH AuthenticationError:
        log.warning("Decryption failed: tampering detected")
        THROW Error("Data integrity check failed")
    END TRY
END FUNCTION
```

## BAD Pattern: ECB Mode

```pseudocode
// VULNERABLE: ECB encrypts identical blocks identically

FUNCTION encrypt_ecb(plaintext, key):
    // Reveals patterns in data!
    cipher = AES.new(key, mode=ECB)
    RETURN cipher.encrypt(pad(plaintext))
END FUNCTION

// Problem: Encrypting an image with ECB preserves visual patterns
// Identical 16-byte blocks produce identical ciphertext
```

## GOOD Pattern: GCM Mode

```pseudocode
// SECURE: Authenticated encryption with unique nonces

FUNCTION encrypt_gcm(plaintext, key):
    // Each encryption is unique even for same plaintext
    nonce = crypto.secure_random_bytes(12)  // 96-bit nonce for GCM

    cipher = AES_GCM.new(key, nonce)
    ciphertext, auth_tag = cipher.encrypt_and_digest(plaintext)

    RETURN nonce + auth_tag + ciphertext
END FUNCTION
```

## BAD Pattern: Static or Reused IVs/Nonces

```pseudocode
// VULNERABLE: Static IV - patterns leak

FUNCTION encrypt_static_iv(plaintext, key):
    // Same IV for all encryptions!
    iv = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    cipher = AES_CBC.new(key, iv)
    RETURN cipher.encrypt(pad(plaintext))
END FUNCTION

// CATASTROPHIC for GCM: Reusing nonce recovers auth key!
```

## GOOD Pattern: Random Nonces

```pseudocode
// SECURE: Random nonce for each encryption

FUNCTION encrypt_with_random_nonce(plaintext, key):
    // New random nonce every time
    nonce = crypto.secure_random_bytes(12)  // 96 bits for AES-GCM

    cipher = AES_GCM.new(key, nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    RETURN nonce + tag + ciphertext
END FUNCTION
```

## BAD Pattern: Rolling Your Own Crypto

```pseudocode
// VULNERABLE: Custom XOR "encryption"

FUNCTION my_encrypt(plaintext, key):
    // Trivially broken with known-plaintext attack
    result = ""
    FOR i = 0 TO plaintext.length - 1:
        result += char(plaintext[i] XOR key[i % key.length])
    END FOR
    RETURN result
END FUNCTION

// Never implement cryptographic primitives yourself!
```

## Algorithm Selection Guide

| Purpose | Use | Avoid |
|---------|-----|-------|
| Symmetric encryption | AES-256-GCM, ChaCha20-Poly1305 | DES, 3DES, RC4, Blowfish |
| Mode of operation | GCM, CCM | ECB, raw CBC without MAC |
| Key size | 256 bits | Less than 128 bits |

## Detection

- Search for `DES`, `3DES`, `RC4`, `Blowfish` in crypto code
- Look for `mode=ECB` or `AES.MODE_ECB`
- Check for static/hardcoded IV or nonce values
- Review for custom XOR or simple cipher implementations
- Verify nonces are generated with secure random

## Prevention Checklist

- [ ] Use AES-256-GCM or ChaCha20-Poly1305 for symmetric encryption
- [ ] Never use DES, 3DES, RC4, or ECB mode
- [ ] Generate random 12-byte nonce for each GCM encryption
- [ ] Never reuse nonces with the same key
- [ ] Use established cryptographic libraries (don't roll your own)
- [ ] Include authentication tags (use authenticated encryption)

## Related Patterns

- [hardcoded-secrets](../hardcoded-secrets/) - Key management
- [insufficient-randomness](../insufficient-randomness/) - Nonce generation
- [weak-password-hashing](../weak-password-hashing/) - Related crypto issues

## References

- [OWASP Top 10 A04:2025 - Cryptographic Failures](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/)
- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
- [CAPEC-97: Cryptanalysis](https://capec.mitre.org/data/definitions/97.html)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
