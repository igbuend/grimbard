---
name: "missing-authentication-anti-pattern"
description: "Security anti-pattern for missing or broken authentication (CWE-287). Use when generating or reviewing code for login systems, API endpoints, protected routes, or access control. Detects unprotected endpoints, weak password policies, and missing rate limiting on authentication."
---

# Missing Authentication Anti-Pattern

**Severity:** Critical

## Summary

Missing or broken authentication occurs when applications fail to verify user identity, allowing unauthorized access to protected data and functionality. This manifests as unprotected endpoints, missing session checks, or weak credential verification vulnerable to bypass or brute-force. AI-generated code frequently produces insecure boilerplate with stubbed or missing authentication checks.

## The Anti-Pattern

Never create endpoints accessing sensitive data or functionality without verifying user identity and validating active sessions.

### BAD Code Example

```python
# VULNERABLE: A critical API endpoint that lacks any authentication check.
from flask import request, jsonify
from db import User, session

@app.route("/api/users/<int:user_id>/profile")
def get_user_profile(user_id):
    # This endpoint takes a user ID and returns the user's profile data.
    # CRITICAL FLAW: It never checks who is making the request.
    # Any user (or an unauthenticated attacker) can request the profile of any other user
    # simply by changing the user_id in the URL.
    user = session.query(User).filter_by(id=user_id).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    # The endpoint returns sensitive profile information to the attacker.
    return jsonify({
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "signed_up_at": user.created_at
    })
```

### GOOD Code Example

```python
# SECURE: The endpoint is protected by an authentication and authorization layer.
from flask import request, jsonify
from db import User, session
from auth import require_authentication # A decorator or middleware for auth.

@app.route("/api/users/<int:user_id>/profile")
@require_authentication # This decorator ensures a valid user session exists.
def get_user_profile_secure(current_user, user_id):
    # The `require_authentication` decorator decodes the session token (e.g., JWT)
    # and passes the authenticated user object (`current_user`) to the function.

    # AUTHORIZATION CHECK:
    # After authenticating, we must now authorize. Is this user allowed to see this data?
    # A user should only be able to see their own profile, unless they are an admin.
    if current_user.id != user_id and not current_user.is_admin:
        return jsonify({"error": "Access denied. You are not authorized to view this profile."}), 403

    user = session.query(User).filter_by(id=user_id).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    # Now it is safe to return the data.
    return jsonify({
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "signed_up_at": user.created_at
    })
```

## Detection

- **Audit all endpoints for authentication:** Grep for routes without auth:
  - `rg '@app\.route|@router\.(get|post)' --type py -A 5 | rg -v '@require|@login|@auth'`
  - `rg 'app\.(get|post|put|delete)\(' --type js -A 3 | rg -v 'authenticate|isAuth'`
  - `rg '@GetMapping|@PostMapping' --type java -A 3 | rg -v '@PreAuthorize|@Secured'`
- **Find sensitive endpoints:** Identify admin, profile, financial routes:
  - `rg '/admin|/api/users|/profile|/account|/payment' -i`
  - Check each for authentication decorators/middleware
- **Check for fail-open logic:** Find default permit patterns:
  - `rg 'if.*not.*authenticated.*return|except.*pass' --type py`
  - `rg 'catch.*\{\s*\}|if.*!auth.*continue' --type js`
- **Test unauthenticated access:** Direct endpoint testing:
  - `curl -X GET https://api.example.com/api/users/me` (no auth header)
  - `curl -X DELETE https://api.example.com/api/admin/users/1` (no token)
  - If these succeed without 401/403, endpoints are vulnerable

## Prevention

- [ ] **Default to deny:** Implement a framework or middleware that requires authentication for all endpoints by default. Endpoints that are intended to be public (like a login or registration page) can be explicitly marked as exempt.
- [ ] **Centralize authentication logic:** Use middleware (in Express), decorators (in Flask/Django), or filters (in Java) to handle authentication checks in a single, reusable, and well-tested place. Avoid repeating authentication logic in every function.
- [ ] **Distinguish between authentication and authorization:**
  - **Authentication** is verifying who the user is.
  - **Authorization** is verifying if that user has permission to perform the requested action. An endpoint must perform both.
- [ ] **Use a robust authentication mechanism:** Implement standard, well-vetted authentication patterns like JWTs, OAuth2, or secure session management. Do not "roll your own" authentication scheme.

## Related Security Patterns & Anti-Patterns

- [Session Fixation Anti-Pattern](../session-fixation/): Relates to how session identifiers are managed after a user logs in.
- [JWT Misuse Anti-Pattern](../jwt-misuse/): Covers common mistakes in implementing token-based authentication.
- [Missing Rate Limiting Anti-Pattern](../missing-rate-limiting/): Login endpoints without rate limiting are vulnerable to brute-force attacks.

## References

- [OWASP Top 10 A07:2025 - Authentication Failures](https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/)
- [OWASP GenAI LLM06:2025 - Excessive Agency](https://genai.owasp.org/llmrisk/llm06-excessive-agency/)
- [OWASP API Security API2:2023 - Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [CAPEC-115: Authentication Bypass](https://capec.mitre.org/data/definitions/115.html)
- [PortSwigger: Authentication](https://portswigger.net/web-security/authentication)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
