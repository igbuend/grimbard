---
name: padding-oracle-anti-pattern
description: Security anti-pattern for padding oracle vulnerabilities (CWE-649). Use when generating or reviewing code that decrypts CBC-mode ciphertext, handles decryption errors, or returns different errors for padding vs other failures. Detects error message oracles.
---

# Padding Oracle Anti-Pattern

**Severity:** High

## Risk

Padding oracle attacks occur when an application reveals whether decrypted data has valid padding. By observing different error responses, attackers can decrypt ciphertext without knowing the key. This leads to:

- Complete plaintext recovery (~128 requests per byte)
- Encryption bypass
- Session token decryption
- Encrypted data exposure

## BAD Pattern: Revealing Padding Validity

```pseudocode
// VULNERABLE: Different errors reveal padding validity

FUNCTION decrypt_cbc_vulnerable(ciphertext, key, iv):
    TRY:
        plaintext = AES_CBC_decrypt(key, iv, ciphertext)
        unpadded = remove_pkcs7_padding(plaintext)
        RETURN {success: TRUE, data: unpadded}
    CATCH PaddingError:
        RETURN {success: FALSE, error: "Invalid padding"}  // ORACLE!
    CATCH DecryptionError:
        RETURN {success: FALSE, error: "Decryption failed"}
    END TRY
END FUNCTION

// Attack process:
// 1. Attacker modifies last byte of ciphertext block
// 2. Sends 256 variations to server
// 3. "Invalid padding" vs "Decryption failed" reveals correct padding
// 4. Repeat for each byte position
// 5. ~128 requests per byte to recover plaintext
```

## BAD Pattern: Timing-Based Oracle

```pseudocode
// VULNERABLE: Timing difference reveals padding validity

FUNCTION decrypt_with_timing_oracle(ciphertext, key, iv):
    TRY:
        plaintext = AES_CBC_decrypt(key, iv, ciphertext)

        // Slow padding check reveals validity through timing
        FOR i = 0 TO length(plaintext) - 1:
            IF is_valid_padding_byte(plaintext, i):
                CONTINUE
            ELSE:
                RETURN {success: FALSE}  // Returns faster on invalid padding
            END IF
        END FOR

        RETURN {success: TRUE, data: plaintext}
    CATCH:
        RETURN {success: FALSE}
    END TRY
END FUNCTION
```

## GOOD Pattern: Authenticate Then Decrypt

```pseudocode
// SECURE: Verify HMAC before any decryption

FUNCTION decrypt_cbc_secure(ciphertext, key, iv):
    TRY:
        // Ciphertext format: IV + ciphertext + HMAC
        // First verify HMAC before any decryption
        provided_hmac = ciphertext[-32:]
        ciphertext_data = ciphertext[:-32]

        expected_hmac = HMAC_SHA256(key, iv + ciphertext_data)

        // Constant-time comparison
        IF NOT constant_time_equals(provided_hmac, expected_hmac):
            RETURN {success: FALSE, error: "Decryption failed"}  // Generic
        END IF

        // Only decrypt after HMAC verification passes
        plaintext = AES_CBC_decrypt(key, iv, ciphertext_data)
        unpadded = remove_pkcs7_padding(plaintext)
        RETURN {success: TRUE, data: unpadded}
    CATCH:
        // Same error for ALL failures
        RETURN {success: FALSE, error: "Decryption failed"}
    END TRY
END FUNCTION
```

## GOOD Pattern: Use Authenticated Encryption (GCM)

```pseudocode
// BEST: Use GCM which prevents padding oracle entirely

FUNCTION encrypt_gcm(plaintext, key):
    // GCM provides encryption + authentication in one operation
    nonce = crypto.secure_random_bytes(12)
    cipher = AES_GCM.new(key, nonce)
    ciphertext, auth_tag = cipher.encrypt_and_digest(plaintext)
    RETURN nonce + auth_tag + ciphertext
END FUNCTION

FUNCTION decrypt_gcm(encrypted_data, key):
    TRY:
        nonce = encrypted_data[0:12]
        auth_tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]

        cipher = AES_GCM.new(key, nonce)
        // decrypt_and_verify checks authentication AND decrypts
        // Fails atomically if tag invalid - no padding oracle possible
        plaintext = cipher.decrypt_and_verify(ciphertext, auth_tag)
        RETURN {success: TRUE, data: plaintext}
    CATCH AuthenticationError:
        // GCM authentication failure - no oracle
        RETURN {success: FALSE, error: "Decryption failed"}
    END TRY
END FUNCTION
```

## GOOD Pattern: Generic Error Messages

```pseudocode
// SECURE: Return identical errors for all decryption failures

FUNCTION decrypt_safe(ciphertext, key):
    TRY:
        // All decryption operations
        result = perform_decryption(ciphertext, key)

        IF NOT result.valid:
            // Generic error - don't reveal reason
            RETURN {success: FALSE, error: "Decryption failed"}
        END IF

        RETURN {success: TRUE, data: result.plaintext}
    CATCH Exception:
        // Catch ALL exceptions with same error
        RETURN {success: FALSE, error: "Decryption failed"}
    END TRY
END FUNCTION
```

## Why CBC Mode is Vulnerable

| Step | CBC Decryption | Padding Oracle Exploit |
|------|----------------|----------------------|
| 1 | Decrypt block with key | Modify ciphertext byte |
| 2 | XOR with previous ciphertext | Observe error response |
| 3 | Check padding validity | "Invalid padding" = wrong guess |
| 4 | Return plaintext or error | "Decryption failed" = correct padding |

## Detection

- Search for CBC decryption code with separate error handling
- Look for `PaddingException` or similar specific catches
- Check if error messages differ between padding and other errors
- Review decryption functions for timing differences
- Test by sending modified ciphertext and observing responses

## Prevention Checklist

- [ ] Use authenticated encryption (AES-GCM, ChaCha20-Poly1305)
- [ ] If using CBC, always Encrypt-then-MAC
- [ ] Verify MAC before attempting decryption
- [ ] Return identical errors for all decryption failures
- [ ] Use constant-time comparison for MAC verification
- [ ] Never reveal whether padding was valid or invalid
- [ ] Log decryption failures without detailed error info

## Related Patterns

- [weak-encryption](../weak-encryption/) - Encryption mode selection
- [timing-attacks](../timing-attacks/) - Related timing side-channel
- [verbose-error-messages](../verbose-error-messages/) - Error disclosure

## References

- [OWASP Top 10 A04:2025 - Cryptographic Failures](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/)
- [CWE-649: Reliance on Obfuscation](https://cwe.mitre.org/data/definitions/649.html)
- [CAPEC-463: Padding Oracle Crypto Attack](https://capec.mitre.org/data/definitions/463.html)
- [Padding Oracle Attack (Vaudenay)](https://en.wikipedia.org/wiki/Padding_oracle_attack)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
