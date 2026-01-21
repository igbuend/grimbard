---
name: "jwt-misuse-anti-pattern"
description: "Security anti-pattern for JWT misuse vulnerabilities (CWE-287). Use when generating or reviewing code that creates, validates, or uses JSON Web Tokens. Detects 'none' algorithm attacks, weak secrets, sensitive data in payloads, and missing expiration."
---

# JWT Misuse Anti-Pattern

**Severity:** High

## Summary

JSON Web Tokens (JWTs) are a common standard for creating access tokens, but they are frequently misused, leading to significant security vulnerabilities. This anti-pattern covers several common JWT implementation flaws often seen in AI-generated code, including accepting the "none" algorithm, using weak secrets, storing sensitive data in the payload, and failing to set an expiration time. These mistakes can lead to authentication bypass, token forgery, and sensitive data exposure.

## The Anti-Patterns and Solutions

### 1. Algorithm Confusion ("none" Algorithm Attack)

A critical vulnerability where a library accepts any algorithm specified in the token's header. An attacker can change the algorithm to "none" and remove the signature, causing the library to validate the token without any cryptographic checks.

#### BAD Code Example

```python
# VULNERABLE: Accepts whatever algorithm is in the header
import jwt

def verify_jwt_vulnerable(token, secret_key):
    # If the token's header is {"alg": "none"}, the library may bypass signature verification entirely.
    try:
        decoded = jwt.decode(token, secret_key, algorithms=None) # algorithms=None or not specified
        return decoded
    except jwt.PyJWTError as e:
        print(f"JWT verification failed: {e}")
        return None
```

#### GOOD Code Example

```python
# SECURE: Explicitly specify allowed algorithms
import jwt

def verify_jwt_secure(token, secret_key):
    # CRITICAL: Always specify the exact algorithm(s) you expect.
    # The library will now reject any token that does not use one of the specified algorithms.
    try:
        decoded = jwt.decode(token, secret_key, algorithms=["HS256", "RS256"])
        return decoded
    except jwt.PyJWTError as e:
        print(f"JWT verification failed: {e}")
        return None
```

### 2. Weak Secret

Using a weak, predictable, or hardcoded secret for symmetric signing algorithms (like HS256) makes it possible for an attacker to brute-force the secret and forge valid tokens.

#### BAD Code Example

```python
# VULNERABLE: Weak or short secret key
import jwt

JWT_SECRET = "secret123"  # Easily brute-forced!

def create_jwt(user_id):
    payload = {"user_id": user_id}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")
```

#### GOOD Code Example

```python
# SECURE: Strong, centrally managed secret
import jwt
import os

# Load a strong, randomly generated secret from environment variables or a secret manager.
JWT_SECRET = os.environ.get("JWT_SECRET")

def initialize():
    if not JWT_SECRET or len(JWT_SECRET) < 32:
        raise ValueError("JWT_SECRET must be at least 256 bits (32 chars) for HS256")

# For production, consider asymmetric keys (e.g., RS256) where the private key is kept secret
# and the public key can be safely distributed for verification.
def create_jwt_asymmetric(user_id, private_key):
    payload = {"sub": user_id}
    return jwt.encode(payload, private_key, algorithm="RS256")
```

### 3. Sensitive Data in Payload

The JWT payload is Base64Url-encoded, not encrypted. Anyone who intercepts the token can easily decode and read the data it contains. Storing sensitive information like PII, passwords, or internal data in the payload is a major security risk.

#### BAD Code Example

```python
# VULNERABLE: Sensitive data in JWT payload
import jwt

def create_jwt_with_pii(user, secret_key):
    payload = {
        "user_id": user.id,
        "email": user.email,
        "ssn": user.social_security_number,  # PII EXPOSED!
        "password_hash": user.password_hash # CRITICAL RISK!
    }
    return jwt.encode(payload, secret_key, algorithm="HS256")
```

#### GOOD Code Example

```python
# SECURE: Minimal, non-sensitive claims
import jwt
import time

def create_jwt_secure(user, secret_key):
    payload = {
        "sub": user.id,          # Subject (user ID) - standard and non-sensitive
        "iat": int(time.time()), # Issued at - standard
        "exp": int(time.time()) + 3600, # Expiration (1 hour) - standard
        "role": user.role        # Non-sensitive custom claim
    }
    # Never include passwords, PII, payment info, or internal data.
    # The server should fetch this data from a secure database using the user ID from the token.
    return jwt.encode(payload, secret_key, algorithm="HS256")
```

## Detection

- Review calls to `jwt.decode()` and ensure the `algorithms` parameter is explicitly set to a list of expected algorithms.
- Search for hardcoded or weak JWT secrets (e.g., `"secret"`, `"password"`, short keys).
- Inspect the data being added to the JWT payload for any sensitive information (PII, credentials, etc.).
- Check for the absence of the `exp` (expiration) claim when creating tokens.

## Prevention

- [ ] **Always specify allowed algorithms** explicitly during token verification.
- [ ] **Use strong, centrally managed secrets** (at least 256 bits for HS256) or prefer asymmetric algorithms (RS256/ES256) for production systems.
- [ ] **Never store sensitive data** in JWT payloads. The payload is readable by anyone.
- [ ] **Always include an `exp` claim** with a reasonably short lifetime for access tokens.
- [ ] **Implement a token refresh mechanism** for sessions that need to last longer than the access token's lifetime.
- [ ] **Consider implementing a token revocation list** to invalidate tokens for compromised accounts.

## Related Security Patterns & Anti-Patterns

- [Hardcoded Secrets Anti-Pattern](../hardcoded-secrets/): JWT secrets are a common type of hardcoded secret.
- [Session Fixation Anti-Pattern](../session-fixation/): Provides context on alternative session management strategies.
- [Insufficient Randomness Anti-Pattern](../insufficient-randomness/): Relevant if generating unique token identifiers (`jti`).

## References

- [OWASP Top 10 A07:2025 - Authentication Failures](https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/)
- [OWASP GenAI LLM06:2025 - Excessive Agency](https://genai.owasp.org/llmrisk/llm06-excessive-agency/)
- [OWASP API Security API2:2023 - Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [CAPEC-220: Client-Server Protocol Manipulation](https://capec.mitre.org/data/definitions/220.html)
- [PortSwigger: Jwt](https://portswigger.net/web-security/jwt)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
