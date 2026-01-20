---
name: session-fixation-anti-pattern
description: Security anti-pattern for session fixation vulnerabilities (CWE-384). Use when generating or reviewing code that handles user sessions, login flows, or authentication state changes. Detects failure to regenerate session IDs after authentication.
---

# Session Fixation Anti-Pattern

**Severity:** High

## Risk

Session fixation occurs when an application doesn't regenerate the session ID after a user authenticates. An attacker can set a victim's session ID before login, then use that same session after the victim authenticates. This leads to:

- Account takeover
- Session hijacking
- Unauthorized access to authenticated sessions

## BAD Pattern: Session Not Regenerated

```pseudocode
// VULNERABLE: Session ID not regenerated on login

FUNCTION login(username, password):
    // Session ID was set when user first visited (before login)
    session_id = request.get_cookie("session_id")

    user = authenticate(username, password)
    IF user IS NULL:
        RETURN {success: FALSE}
    END IF

    // Vulnerable: Reusing pre-authentication session ID
    session_store.set(session_id, {user_id: user.id, authenticated: TRUE})
    RETURN {success: TRUE}
END FUNCTION

// Attack scenario:
// 1. Attacker visits site, gets session_id=ABC123
// 2. Attacker sends victim link: https://site.com?session_id=ABC123
// 3. Victim logs in with attacker's session ID
// 4. Attacker uses session_id=ABC123 to access victim's account
```

## GOOD Pattern: Regenerate Session on Auth Changes

```pseudocode
// SECURE: Regenerate session on authentication changes

FUNCTION login(username, password):
    user = authenticate(username, password)
    IF user IS NULL:
        RETURN {success: FALSE}
    END IF

    // CRITICAL: Invalidate old session and create new one
    old_session_id = request.get_cookie("session_id")
    IF old_session_id IS NOT NULL:
        session_store.delete(old_session_id)
    END IF

    // Generate completely new session ID
    new_session = create_secure_session(user.id)

    // Set new session cookie with security flags
    response.set_cookie("session_id", new_session.token, {
        httponly: TRUE,      // Prevent JavaScript access
        secure: TRUE,        // HTTPS only
        samesite: "Strict"   // Prevent CSRF
    })

    RETURN {success: TRUE}
END FUNCTION

FUNCTION create_secure_session(user_id):
    // Generate cryptographically secure random token
    token_bytes = crypto.secure_random_bytes(32)
    token = base64_url_encode(token_bytes)

    session_data = {
        user_id: user_id,
        created_at: current_timestamp(),
        expires_at: current_timestamp() + SESSION_LIFETIME
    }

    // Store hashed token (protect against database leaks)
    token_hash = sha256(token)
    session_store.set(token_hash, session_data)

    RETURN {token: token, data: session_data}
END FUNCTION
```

## Additional Scenarios Requiring Session Regeneration

```pseudocode
// Also regenerate session on privilege escalation
FUNCTION elevate_privileges(user, new_role):
    old_session_id = request.get_cookie("session_id")
    session_store.delete(old_session_id)

    new_session = create_secure_session(user.id)
    new_session.data.role = new_role

    response.set_cookie("session_id", new_session.token, {
        httponly: TRUE,
        secure: TRUE,
        samesite: "Strict"
    })

    RETURN new_session
END FUNCTION

// Regenerate on logout (full invalidation)
FUNCTION logout():
    session_id = request.get_cookie("session_id")
    IF session_id IS NOT NULL:
        session_store.delete(sha256(session_id))
    END IF

    // Clear the cookie
    response.delete_cookie("session_id")
    RETURN {success: TRUE}
END FUNCTION

// Regenerate periodically for long-lived sessions
FUNCTION check_session_rotation(session):
    // Rotate session every 15 minutes for active users
    IF current_timestamp() - session.created_at > 900:
        new_session = create_secure_session(session.user_id)
        new_session.data = session.data  // Preserve session data

        session_store.delete(session.id)

        response.set_cookie("session_id", new_session.token, {
            httponly: TRUE,
            secure: TRUE,
            samesite: "Strict"
        })

        RETURN new_session
    END IF

    RETURN session
END FUNCTION
```

## Detection

- Look for login functions that don't create new session IDs
- Search for session handling without `regenerate_id()` or equivalent
- Check if session cookies are set with proper security flags
- Review privilege escalation flows for session regeneration

## Prevention Checklist

- [ ] Regenerate session ID immediately after successful authentication
- [ ] Regenerate session ID on privilege level changes
- [ ] Invalidate old session data when creating new session
- [ ] Set session cookies with `HttpOnly`, `Secure`, and `SameSite` flags
- [ ] Implement session timeout and idle timeout
- [ ] Consider periodic session rotation for long-lived sessions

## Related Patterns

- [missing-authentication](../missing-authentication/) - Authentication fundamentals
- [jwt-misuse](../jwt-misuse/) - Token-based session alternatives
- [insufficient-randomness](../insufficient-randomness/) - Secure session ID generation

## References

- [OWASP Top 10 A07:2021 - Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
- [CAPEC-61: Session Fixation](https://capec.mitre.org/data/definitions/61.html)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
