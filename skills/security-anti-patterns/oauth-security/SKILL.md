---
name: "oauth-security-anti-pattern"
description: "Security anti-pattern for OAuth implementation vulnerabilities (CWE-352, CWE-287). Use when generating or reviewing OAuth/OIDC authentication flows, state parameter handling, or token exchange. Detects missing CSRF protection and insecure redirect handling."
---

# OAuth Security Anti-Pattern

**Severity:** High

## Summary

OAuth 2.0 and OpenID Connect (OIDC) are powerful standards for delegated authentication and authorization, but they are complex and easy to misconfigure. This anti-pattern covers one of the most critical and common mistakes: **failing to properly implement and validate the `state` parameter**. The `state` parameter is the primary defense against Cross-Site Request Forgery (CSRF) attacks during an OAuth flow. A missing or predictable `state` parameter allows an attacker to trick a victim into logging into the attacker's account, potentially leading to account takeover.

## The Anti-Pattern

The anti-pattern is initiating an OAuth flow without a `state` parameter, or using one that is predictable or not validated upon the user's return to the application.

### BAD Code Example

```python
# VULNERABLE: The OAuth flow is initiated without a `state` parameter.
from flask import request, redirect

OAUTH_PROVIDER_URL = "https://provider.com/auth"
CLIENT_ID = "my-client-id"
CALLBACK_URL = "https://myapp.com/callback"

@app.route("/login/provider")
def oauth_login():
    # The application redirects the user to the OAuth provider.
    # CRITICAL FLAW: There is no `state` parameter to prevent CSRF.
    auth_url = (f"{OAUTH_PROVIDER_URL}?client_id={CLIENT_ID}"
                f"&redirect_uri={CALLBACK_URL}&response_type=code")
    return redirect(auth_url)

@app.route("/callback")
def oauth_callback():
    # The user is redirected back here from the provider.
    # The application receives the authorization code but has no way to verify
    # if this callback corresponds to a flow the user actually initiated.
    auth_code = request.args.get("code")
    # The application proceeds to exchange the code for tokens and logs the user in.
    # An attacker can exploit this to link the victim's session to their (the attacker's) account.
    access_token = exchange_code_for_token(auth_code)
    log_user_in(access_token)
    return "Logged in successfully!"
```

**Attack Scenario:**

1. Attacker starts an OAuth flow with their own account at the provider.
2. The provider redirects the attacker back to `https://myapp.com/callback?code=ATTACKER_CODE`.
3. The attacker intercepts this request and pauses it. They now have a valid callback URL containing an authorization code for their own account.
4. The attacker tricks the victim (who is already logged into `myapp.com`) into visiting this malicious URL.
5. `myapp.com` receives the callback, takes the `ATTACKER_CODE`, and associates the victim's session with the attacker's provider account. The victim's account is now linked to the attacker's identity.

### GOOD Code Example

```python
# SECURE: A unique, unpredictable `state` is generated, stored in the session, and validated on callback.
from flask import request, redirect, session
import secrets

@app.route("/login/provider/secure")
def oauth_login_secure():
    # 1. Generate a cryptographically random, unpredictable value for `state`.
    state = secrets.token_urlsafe(32)
    # 2. Store this value in the user's session.
    session['oauth_state'] = state

    auth_url = (f"{OAUTH_PROVIDER_URL}?client_id={CLIENT_ID}"
                f"&redirect_uri={CALLBACK_URL}&response_type=code"
                f"&state={state}") # 3. Send the state to the provider.
    return redirect(auth_url)

@app.route("/callback/secure")
def oauth_callback_secure():
    # 4. The provider returns the `state` value in the callback.
    received_state = request.args.get("state")
    auth_code = request.args.get("code")

    # 5. CRITICAL VALIDATION: Check that the returned state matches the one from the session.
    stored_state = session.pop('oauth_state', None)
    if stored_state is None or not secrets.compare_digest(stored_state, received_state):
        return "Invalid state parameter. CSRF attack detected.", 403

    # If the state is valid, it's safe to proceed.
    access_token = exchange_code_for_token(auth_code)
    log_user_in(access_token)
    return "Logged in successfully!"
```

## Detection

- **Trace the OAuth flow:** Start at the point where your application redirects to the OAuth provider.
  - Is a `state` parameter being generated?
  - Is it cryptographically random and unpredictable?
- **Examine the callback endpoint:**
  - Does it retrieve the `state` from the incoming request?
  - Does it compare it to a value stored in the user's session *before* the redirect?
  - Is the comparison done in constant time (`hmac.compare_digest`) to prevent timing attacks?
  - Is the state value single-use (i.e., deleted from the session after being checked)?

## Prevention

- [ ] **Always use a `state` parameter** in your OAuth/OIDC authorization requests.
- [ ] **Generate a cryptographically random string** for the `state` value (at least 32 characters). Do not use predictable values like a user ID or timestamp.
- [ ] **Bind the `state` value to the user's current session** by storing it in a session cookie before redirecting the user.
- [ ] **On the callback, strictly compare** the `state` parameter from the request with the value stored in the session. Reject the request if they do not match.
- [ ] **Make the `state` value single-use.** Once it has been validated, immediately remove it from the session to prevent replay attacks.
- [ ] **For public clients (SPAs, mobile apps), use the PKCE** (Proof Key for Code Exchange) extension in addition to the `state` parameter.

## Related Security Patterns & Anti-Patterns

- [Session Fixation Anti-Pattern](../session-fixation/): A successful OAuth CSRF attack is a form of session fixation.
- [Insufficient Randomness Anti-Pattern](../insufficient-randomness/): The `state` parameter must be generated with a cryptographically secure random number generator.
- [Missing Authentication Anti-Pattern](../missing-authentication/): OAuth is a form of authentication, and its flows must be implemented correctly to be secure.

## References

- [OWASP Top 10 A07:2025 - Authentication Failures](https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/)
- [OWASP GenAI LLM06:2025 - Excessive Agency](https://genai.owasp.org/llmrisk/llm06-excessive-agency/)
- [OWASP API Security API2:2023 - Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)
- [OWASP OAuth Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth_Cheat_Sheet.html)
- [CWE-352: Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)
- [CAPEC-103: Clickjacking](https://capec.mitre.org/data/definitions/103.html)
- [PortSwigger: Oauth](https://portswigger.net/web-security/oauth)
- [OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
