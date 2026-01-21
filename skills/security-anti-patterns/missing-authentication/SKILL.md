---
name: "missing-authentication-anti-pattern"
description: "Security anti-pattern for missing or broken authentication (CWE-287). Use when generating or reviewing code for login systems, API endpoints, protected routes, or access control. Detects unprotected endpoints, weak password policies, and missing rate limiting on authentication."
---

# Missing Authentication Anti-Pattern

**Severity:** Critical

## Summary
Missing or broken authentication is a critical vulnerability that occurs when an application fails to correctly verify the identity of a user, allowing attackers to access protected data or functionality. This anti-pattern is one of the most common and damaging security flaws. It can manifest as completely unprotected endpoints, a failure to check for a valid session, or weak credential verification processes that can be easily bypassed or brute-forced. AI-generated code can often produce insecure boilerplate where authentication and authorization checks are stubbed out or missing entirely.

## The Anti-Pattern
The core anti-pattern is creating an endpoint that provides access to sensitive data or functionality without first performing a robust check to confirm that the user is who they claim to be and that they have a valid, active session.

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
- **Review all endpoints:** Systematically check every API endpoint and web route to ensure that it has an authentication check before any data is accessed or any action is performed.
- **Identify sensitive functionality:** Pay close attention to endpoints that handle user profiles, administrative actions, financial transactions, or any other sensitive data.
- **Check for "fail-open" logic:** Ensure that the default behavior is to deny access. The code should actively grant access upon successful authentication, not the other way around.
- **Test endpoints directly:** Use a tool like `curl` or Postman to make requests to sensitive endpoints without providing any authentication token or session cookie. If the request succeeds, the endpoint is vulnerable.

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
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
