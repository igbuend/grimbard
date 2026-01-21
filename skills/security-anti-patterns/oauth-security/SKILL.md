---
name: oauth-security-anti-pattern
description: Security anti-pattern for OAuth implementation vulnerabilities (CWE-352, CWE-287). Use when generating or reviewing OAuth/OIDC authentication flows, state parameter handling, or token exchange. Detects missing CSRF protection and insecure redirect handling.
---

# OAuth Security Anti-Pattern

**Severity:** High

## Risk

OAuth implementations frequently contain CSRF vulnerabilities, predictable state parameters, and missing validations. AI-generated code often produces minimal OAuth flows missing critical security controls. This leads to:

- Account takeover via CSRF
- Authorization code interception
- Session fixation through OAuth
- Token theft and replay

## BAD Pattern: Missing State Parameter

```pseudocode
// VULNERABLE: No state parameter - CSRF possible

FUNCTION initiate_oauth_vulnerable():
    redirect_url = OAUTH_PROVIDER_URL +
        "?client_id=" + CLIENT_ID +
        "&redirect_uri=" + CALLBACK_URL +
        "&scope=email profile"
    RETURN redirect(redirect_url)
END FUNCTION

// Attack: Attacker initiates OAuth flow, gets callback URL
// Tricks victim into visiting callback URL
// Victim's account linked to attacker's OAuth identity
```

## BAD Pattern: Predictable State

```pseudocode
// VULNERABLE: Predictable state parameter

FUNCTION initiate_oauth_weak_state():
    state = to_string(current_timestamp())  // Predictable!
    // Or: state = md5(user_id)  // Also predictable
    // Or: state = session_id  // Reusable across sessions

    store_state(state)
    redirect_url = OAUTH_PROVIDER_URL +
        "?client_id=" + CLIENT_ID +
        "&state=" + state +
        "&redirect_uri=" + CALLBACK_URL
    RETURN redirect(redirect_url)
END FUNCTION
```

## BAD Pattern: State Not Validated

```pseudocode
// VULNERABLE: State parameter ignored on callback

FUNCTION handle_callback_vulnerable(request):
    code = request.query.code
    // state parameter completely ignored!

    tokens = exchange_code_for_tokens(code)
    RETURN login_with_tokens(tokens)
END FUNCTION
```

## BAD Pattern: State Reuse

```pseudocode
// VULNERABLE: State not invalidated after use

FUNCTION handle_callback_reuse_vulnerable(request):
    code = request.query.code
    state = request.query.state

    IF is_valid_state(state):  // Just checks existence
        // State NOT deleted - can be reused!
        tokens = exchange_code_for_tokens(code)
        RETURN login_with_tokens(tokens)
    END IF

    RETURN error("Invalid state")
END FUNCTION
```

## GOOD Pattern: Complete OAuth Implementation

```pseudocode
// SECURE: Full OAuth with all protections

FUNCTION initiate_oauth_secure(request):
    // Generate cryptographically random state
    state = generate_secure_random(32)

    // Bind state to user's session (CSRF protection)
    request.session.oauth_state = state
    request.session.oauth_state_created_at = current_timestamp()

    // Include nonce for ID token validation (OIDC)
    nonce = generate_secure_random(32)
    request.session.oauth_nonce = nonce

    redirect_url = OAUTH_PROVIDER_URL +
        "?client_id=" + CLIENT_ID +
        "&response_type=code" +
        "&redirect_uri=" + url_encode(CALLBACK_URL) +
        "&scope=" + url_encode("openid email profile") +
        "&state=" + state +
        "&nonce=" + nonce

    RETURN redirect(redirect_url)
END FUNCTION

FUNCTION handle_callback_secure(request):
    code = request.query.code
    state = request.query.state
    error = request.query.error

    // Check for OAuth error
    IF error:
        log_oauth_error(error, request.query.error_description)
        RETURN redirect("/login?error=oauth_failed")
    END IF

    // Validate state exists
    IF NOT state:
        RETURN error("Missing state parameter")
    END IF

    stored_state = request.session.oauth_state
    state_created_at = request.session.oauth_state_created_at

    // Constant-time comparison prevents timing attacks
    IF NOT constant_time_equals(state, stored_state):
        log_security_event("OAuth state mismatch", request)
        RETURN error("Invalid state")
    END IF

    // Check state expiry (5 minutes max)
    IF current_timestamp() - state_created_at > 300:
        RETURN error("OAuth session expired")
    END IF

    // Clear state immediately (one-time use)
    DELETE request.session.oauth_state
    DELETE request.session.oauth_state_created_at

    // Exchange code for tokens
    token_response = exchange_code_for_tokens(code, CALLBACK_URL)

    IF NOT token_response.id_token:
        RETURN error("Missing ID token")
    END IF

    // Validate ID token including nonce
    id_token = verify_id_token(token_response.id_token, {
        audience: CLIENT_ID,
        nonce: request.session.oauth_nonce
    })

    DELETE request.session.oauth_nonce

    IF NOT id_token.valid:
        RETURN error("Invalid ID token")
    END IF

    // Create authenticated session
    user = find_or_create_user_from_oauth(id_token.payload)
    create_authenticated_session(request, user)

    RETURN redirect("/dashboard")
END FUNCTION
```

## OAuth Security Checklist

| Check | Requirement |
|-------|-------------|
| State parameter | Cryptographically random, session-bound |
| State validation | Constant-time comparison |
| State lifetime | Short expiry (5-10 minutes) |
| State usage | Single-use, deleted after callback |
| Nonce (OIDC) | Random, verified in ID token |
| Redirect URI | Exact match, not pattern |
| PKCE | Required for public clients |

## Detection

- Search for OAuth redirects without state parameter
- Check if state is validated on callback
- Look for predictable state generation (timestamps, hashes of user data)
- Verify state is deleted after successful use
- Check for PKCE implementation in SPAs/mobile apps

## Prevention Checklist

- [ ] Generate cryptographically random state (32+ bytes)
- [ ] Bind state to user session
- [ ] Validate state with constant-time comparison
- [ ] Delete state after single use
- [ ] Set short expiry for state (5-10 minutes)
- [ ] Use PKCE for public clients (SPAs, mobile apps)
- [ ] Validate redirect_uri exactly matches registered URI
- [ ] Verify ID token nonce for OIDC flows

## Related Patterns

- [session-fixation](../session-fixation/) - OAuth can cause session fixation
- [missing-authentication](../missing-authentication/) - OAuth is authentication
- [insufficient-randomness](../insufficient-randomness/) - State generation

## References

- [OWASP Top 10 A07:2025 - Authentication Failures](https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/)
- [OWASP OAuth Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth_Cheat_Sheet.html)
- [CWE-352: Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)
- [CAPEC-103: Clickjacking](https://capec.mitre.org/data/definitions/103.html)
- [OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
