---
name: "open-cors-anti-pattern"
description: "Security anti-pattern for open Cross-Origin Resource Sharing (CORS) policies (CWE-942). Use when generating or reviewing server configurations, API backends, or any code that sets CORS headers. Detects overly permissive Access-Control-Allow-Origin headers, including wildcard, null origin, and reflected origin."
---

# Open CORS Policy Anti-Pattern

**Severity:** Medium

## Summary

Cross-Origin Resource Sharing (CORS) is a browser security feature that controls how web pages from one domain can request resources from another domain. A misconfigured, overly permissive CORS policy is a common vulnerability. This anti-pattern occurs when a server responds with `Access-Control-Allow-Origin: *` or dynamically reflects the client's `Origin` header. This allows *any* website on the internet to make authenticated requests to your application on behalf of your users, potentially leading to data theft and unauthorized actions.

## The Anti-Pattern

The anti-pattern is configuring the `Access-Control-Allow-Origin` header to a value that is too permissive, such as the wildcard (`*`) or reflecting any value sent by the client in the `Origin` header.

### BAD Code Example

```python
# VULNERABLE: The server reflects any Origin header, or uses a wildcard with credentials.
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.after_request
def add_cors_headers(response):
    # DANGEROUS: Reflecting the Origin header.
    # An attacker's site (https://evil.com) can now make requests.
    origin = request.headers.get('Origin')
    if origin:
        response.headers['Access-Control-Allow-Origin'] = origin

    # DANGEROUS: Wildcard `*` combined with `Allow-Credentials`.
    # Most browsers block this, but it's a critical misconfiguration.
    # response.headers['Access-Control-Allow-Origin'] = '*'
    # response.headers['Access-Control-Allow-Credentials'] = 'true'

    return response

@app.route("/api/user/profile")
def get_profile():
    # This endpoint is intended to be called by your frontend application.
    # It relies on the user's session cookie for authentication.
    user = get_user_from_session()
    return jsonify(user.to_dict())

# Attack Scenario:
# 1. A logged-in user of your site visits https://evil.com.
# 2. A script on evil.com makes a `fetch` request to `https://yourapp.com/api/user/profile`.
# 3. Because of the permissive CORS policy, the browser allows this request,
#    and importantly, it attaches the user's session cookie.
# 4. Your server receives a valid, authenticated request and responds with the user's sensitive profile data.
# 5. The script on evil.com now has the user's data and can send it to the attacker.
```

### GOOD Code Example

```python
# SECURE: Maintain a strict allowlist of trusted origins.
from flask import Flask, request, jsonify

app = Flask(__name__)

# Define a strict allowlist of origins that are permitted to access your API.
ALLOWED_ORIGINS = {
    "https://www.yourapp.com",
    "https://yourapp.com",
    "https://staging.yourapp.com"
}

@app.after_request
def add_secure_cors_headers(response):
    origin = request.headers.get('Origin')
    if origin in ALLOWED_ORIGINS:
        # Only set the header if the origin is in the trusted list.
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        # Vary header tells caches that the response depends on the Origin.
        response.headers['Vary'] = 'Origin'
    return response

@app.route("/api/user/profile")
def get_profile_secure():
    user = get_user_from_session()
    return jsonify(user.to_dict())

# Now, when a script from https://evil.com tries to make a request,
# the `origin` is not in the `ALLOWED_ORIGINS` set, so no CORS headers are sent.
# The browser's same-origin policy blocks the request, protecting the user's data.
```

## Detection

- **Use browser developer tools:** Open the "Network" tab, make a cross-origin request to your API, and inspect the response headers. Look for `Access-Control-Allow-Origin`. Is it `*`? Does it match the `Origin` of your request even if that origin is untrusted?
- **Use `curl`:** Make a request and set a custom `Origin` header to see if the server reflects it:
  `curl -H "Origin: https://evil.com" -I https://yourapp.com/api/some-endpoint`
  Check if the response contains `Access-Control-Allow-Origin: https://evil.com`.
- **Review CORS configuration:** Check your application's code or framework configuration for how CORS headers are being set. Look for wildcards or reflected origins.

## Prevention

- [ ] **Maintain a strict allowlist** of trusted origins. This is the most critical step.
- [ ] **Never reflect the user-provided `Origin` header** without validating it against the allowlist first.
- [ ] **Do not use the wildcard (`*`)** for `Access-Control-Allow-Origin` on any endpoint that requires authentication (e.g., uses cookies or `Authorization` headers). A wildcard is only safe for truly public, unauthenticated resources.
- [ ] **Set `Access-Control-Allow-Credentials` to `true`** only when necessary and only for origins on your allowlist.
- [ ] **Add the `Vary: Origin` header** to tell caches that the response is origin-dependent. This prevents a cached response intended for a trusted origin from being served to a malicious one.

## Related Security Patterns & Anti-Patterns

- [Missing Security Headers Anti-Pattern](../missing-security-headers/): CORS is a key part of the broader suite of security headers an application must manage.
- [Cross-Site Scripting (XSS) Anti-Pattern](../xss/): An attacker could use a permissive CORS policy to exfiltrate data stolen via an XSS attack.

## References

- [OWASP Top 10 A02:2025 - Security Misconfiguration](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/)
- [OWASP GenAI LLM07:2025 - System Prompt Leakage](https://genai.owasp.org/llmrisk/llm07-system-prompt-leakage/)
- [OWASP API Security API8:2023 - Security Misconfiguration](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/)
- [OWASP CORS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html)
- [CWE-942: Permissive Cross-domain Policy with Untrusted Domains](https://cwe.mitre.org/data/definitions/942.html)
- [PortSwigger - CORS Vulnerabilities](https://portswigger.net/web-security/cors)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
