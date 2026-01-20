---
name: jwt-misuse-anti-pattern
description: Security anti-pattern for JWT misuse vulnerabilities (CWE-287). Use when generating or reviewing code that creates, validates, or uses JSON Web Tokens. Detects none algorithm attacks, weak secrets, sensitive data in payloads, and missing expiration.
---

# JWT Misuse Anti-Pattern

**Severity:** High

## Risk

JWTs are frequently misused in AI-generated code due to outdated tutorials in training data. Common mistakes include accepting the "none" algorithm, using weak secrets, storing sensitive data in payloads (which are only base64-encoded, not encrypted), and missing expiration. This leads to:

- Authentication bypass via algorithm confusion
- Token forgery with weak secrets
- Data exposure from readable payloads
- Permanent access with non-expiring tokens

## BAD Pattern: None Algorithm Attack

```pseudocode
// VULNERABLE: Accepts whatever algorithm is in the header

FUNCTION verify_jwt_vulnerable(token):
    // Attacker can set alg: "none" to bypass signature verification
    decoded = jwt.decode(token, SECRET_KEY)
    RETURN decoded
END FUNCTION

// Attack: Attacker modifies header to {"alg": "none"} and removes signature
// Result: Token validates without any cryptographic verification
```

## GOOD Pattern: Explicit Algorithm Verification

```pseudocode
// SECURE: Explicitly specify allowed algorithms

FUNCTION verify_jwt_secure(token):
    TRY:
        // CRITICAL: Only accept expected algorithms
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        RETURN decoded
    CATCH JWTError AS e:
        log.warning("JWT verification failed", {error: e.message})
        RETURN NULL
    END TRY
END FUNCTION
```

## BAD Pattern: Weak Secret

```pseudocode
// VULNERABLE: Weak or short secret key

CONSTANT JWT_SECRET = "secret123"  // Easily brute-forced!
CONSTANT JWT_SECRET = "password"   // Common word
CONSTANT JWT_SECRET = "jwt-key"    // Too short

FUNCTION create_jwt(user_id):
    payload = {user_id: user_id}
    RETURN jwt.encode(payload, JWT_SECRET, algorithm="HS256")
END FUNCTION
```

## GOOD Pattern: Strong Secret

```pseudocode
// SECURE: Strong secret from environment

CONSTANT JWT_SECRET = environment.get("JWT_SECRET")  // From secret manager

FUNCTION initialize():
    // Validate secret strength at startup
    IF JWT_SECRET IS NULL OR JWT_SECRET.length < 32:
        THROW Error("JWT_SECRET must be at least 256 bits (32 chars)")
    END IF
END FUNCTION

// For production: Use asymmetric keys (RS256, ES256)
FUNCTION create_jwt_asymmetric(user_id):
    private_key = load_private_key("jwt_private.pem")
    payload = {sub: user_id, exp: current_time() + 3600}
    RETURN jwt.encode(payload, private_key, algorithm="RS256")
END FUNCTION
```

## BAD Pattern: Sensitive Data in Payload

```pseudocode
// VULNERABLE: Sensitive data in JWT payload
// JWTs are base64-encoded, NOT encrypted - anyone can read the payload!

FUNCTION create_jwt_exposed(user):
    payload = {
        user_id: user.id,
        email: user.email,
        ssn: user.social_security_number,  // PII exposed!
        credit_card: user.card_number,      // Payment data exposed!
        password_hash: user.password_hash,  // Never put this in JWT!
        internal_notes: user.admin_notes    // Internal data leaked!
    }
    RETURN jwt.encode(payload, SECRET_KEY)
END FUNCTION
```

## GOOD Pattern: Minimal Non-Sensitive Claims

```pseudocode
// SECURE: Only non-sensitive data in payload

FUNCTION create_jwt_secure(user):
    now = current_time()

    payload = {
        // Standard claims
        sub: user.id,           // Subject (user ID only)
        iat: now,               // Issued at
        exp: now + 3600,        // Expiration (1 hour for access tokens)
        nbf: now,               // Not before

        // Custom claims (non-sensitive only)
        role: user.role         // Roles are OK
        // Never include: passwords, PII, payment info, internal data
    }

    RETURN jwt.encode(payload, JWT_SECRET, algorithm="HS256")
END FUNCTION
```

## BAD Pattern: No Expiration

```pseudocode
// VULNERABLE: No expiration or very long expiration

FUNCTION create_jwt_no_expiry(user_id):
    payload = {user_id: user_id}  // No exp claim!
    RETURN jwt.encode(payload, SECRET_KEY)
END FUNCTION

FUNCTION create_jwt_long_expiry(user_id):
    payload = {
        user_id: user_id,
        exp: current_time() + (365 * 24 * 3600)  // 1 year - too long!
    }
    RETURN jwt.encode(payload, SECRET_KEY)
END FUNCTION
```

## GOOD Pattern: Appropriate Expiration with Refresh

```pseudocode
// SECURE: Short-lived access tokens with refresh tokens

FUNCTION create_tokens(user_id):
    now = current_time()

    // Access token: short-lived (15 min - 1 hour)
    access_payload = {
        sub: user_id,
        type: "access",
        exp: now + 900  // 15 minutes
    }
    access_token = jwt.encode(access_payload, JWT_SECRET, algorithm="HS256")

    // Refresh token: longer-lived, stored securely
    refresh_payload = {
        sub: user_id,
        type: "refresh",
        exp: now + (7 * 24 * 3600),  // 7 days
        jti: generate_unique_id()     // Token ID for revocation
    }
    refresh_token = jwt.encode(refresh_payload, JWT_SECRET, algorithm="HS256")

    // Store refresh token ID for revocation capability
    store_refresh_token(user_id, refresh_payload.jti)

    RETURN {access_token, refresh_token}
END FUNCTION
```

## Detection

- Look for `jwt.decode()` without explicit `algorithms` parameter
- Search for JWT secrets that are hardcoded or short
- Check JWT payloads for sensitive data (PII, credentials, internal info)
- Review for missing `exp` claim or very long expiration times
- Check for algorithm confusion (HS256 vs RS256 key confusion)

## Prevention Checklist

- [ ] Always specify allowed algorithms explicitly in decode
- [ ] Use secrets of at least 256 bits (32 characters) for HS256
- [ ] Consider asymmetric algorithms (RS256, ES256) for production
- [ ] Never store sensitive data in JWT payloads
- [ ] Always include `exp` claim with reasonable duration
- [ ] Implement token refresh mechanism for long sessions
- [ ] Store refresh token IDs for revocation capability

## Related Patterns

- [hardcoded-secrets](../hardcoded-secrets/) - JWT secrets often hardcoded
- [session-fixation](../session-fixation/) - Alternative session approaches
- [insufficient-randomness](../insufficient-randomness/) - Token ID generation

## References

- [OWASP Top 10 A07:2021 - Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [CAPEC-220: Client-Server Protocol Manipulation](https://capec.mitre.org/data/definitions/220.html)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
