---
name: "missing-security-headers-anti-pattern"
description: "Security anti-pattern for missing security headers (CWE-16). Use when generating or reviewing web application code, server configuration, or HTTP response handling. Detects missing CSP, HSTS, X-Frame-Options, and other protective headers."
---

# Missing Security Headers Anti-Pattern

**Severity:** Medium

## Summary
HTTP security headers are a crucial, browser-level defense mechanism against common web application attacks like Cross-Site Scripting (XSS), clickjacking, and man-in-the-middle attacks. This anti-pattern occurs when a web application fails to send these headers in its HTTP responses. Without them, the application is leaving the browser to rely on default, often less secure, behaviors, thereby missing an opportunity for a powerful, declarative security layer.

## The Anti-Pattern
The anti-pattern is simply not including recommended security headers in HTTP responses. By default, browsers have permissive policies, and it is the server's responsibility to instruct the browser to enforce stricter security controls.

### BAD Code Example
```python
# VULNERABLE: A Flask application that does not set any security headers.
from flask import Flask, make_response

app = Flask(__name__)

@app.route("/")
def index():
    # The response is sent with default headers, which are not secure.
    # - No Content-Security-Policy means scripts from any origin can be executed.
    # - No X-Frame-Options means any site can embed this page in an iframe for clickjacking.
    # - No HSTS means the connection can be downgraded to HTTP on the first visit.
    response = make_response("<h1>Welcome to the site!</h1>")
    return response

# The HTTP response would look something like this:
#
# HTTP/1.1 200 OK
# Content-Type: text/html; charset=utf-8
# Content-Length: 29
#
# <h1>Welcome to the site!</h1>
```

### GOOD Code Example
```python
# SECURE: The application sets a strong baseline of security headers for all responses.
from flask import Flask, make_response

app = Flask(__name__)

@app.after_request
def add_security_headers(response):
    # Content-Security-Policy (CSP): A powerful tool to prevent XSS.
    # This policy allows resources (scripts, styles, etc.) only from the same origin ('self').
    response.headers['Content-Security-Policy'] = "default-src 'self'"

    # X-Frame-Options: Prevents the page from being rendered in an iframe, mitigating clickjacking.
    response.headers['X-Frame-Options'] = 'DENY'

    # HTTP Strict-Transport-Security (HSTS): Instructs the browser to only communicate using HTTPS.
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

    # X-Content-Type-Options: Prevents the browser from MIME-sniffing a response away from the declared content-type.
    response.headers['X-Content-Type-Options'] = 'nosniff'

    # Referrer-Policy: Controls how much referrer information is sent with requests.
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

@app.route("/")
def index_secure():
    return make_response("<h1>Welcome to the secure site!</h1>")

# The HTTP response now includes critical security controls:
#
# HTTP/1.1 200 OK
# Content-Type: text/html; charset=utf-8
# Content-Length: 36
# Content-Security-Policy: default-src 'self'
# X-Frame-Options: DENY
# Strict-Transport-Security: max-age=31536000; includeSubDomains
# X-Content-Type-Options: nosniff
# Referrer-Policy: strict-origin-when-cross-origin
#
# <h1>Welcome to the secure site!</h1>
```

## Detection
- **Use browser developer tools:** Open the "Network" tab, inspect a request to your site, and look at the "Response Headers" section. Check for the presence of the headers listed below.
- **Use an online scanner:** Tools like [SecurityHeaders.com](https://securityheaders.com/) can quickly scan a public website and report on its missing headers.
- **Review framework configurations:** Check your web server or framework's configuration files to see if security headers are being set globally. Many frameworks have dedicated middleware (like `Helmet` for Express.js) to handle this.

## Prevention
Implement a middleware or a global response filter in your application that adds the following headers to all outgoing responses.

- [ ] **`Content-Security-Policy` (CSP):** The most important header for preventing XSS. It defines a strict allowlist of sources from which content (like scripts, styles, and images) can be loaded. A good starting point is `default-src 'self'`.
- [ ] **`Strict-Transport-Security` (HSTS):** Instructs the browser that it should only ever communicate with the site using HTTPS. This prevents downgrade attacks.
- [ ] **`X-Frame-Options`:** Prevents your site from being embedded in an `<iframe>` on other sites, which is the primary defense against clickjacking. Set to `DENY` or `SAMEORIGIN`.
- [ ] **`X-Content-Type-Options`:** Set to `nosniff` to prevent the browser from trying to guess the content type of a resource, which can be abused to execute malicious scripts.
- [ ] **`Referrer-Policy`:** Controls how much referrer information is sent when a user navigates away from your site. A good default is `strict-origin-when-cross-origin`.
- [ ] **`Permissions-Policy` (formerly Feature-Policy):** Allows you to selectively enable or disable browser features and APIs (like microphone, camera, geolocation) on your site.

## Related Security Patterns & Anti-Patterns
- [Cross-Site Scripting (XSS) Anti-Pattern](../xss/): A strong Content-Security-Policy is a critical defense-in-depth measure against XSS.
- [Open CORS Anti-Pattern](../open-cors/): Another type of security misconfiguration related to HTTP headers.

## References
- [OWASP Top 10 A02:2025 - Security Misconfiguration](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/)
- [OWASP GenAI LLM02:2025 - Sensitive Information Disclosure](https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/)
- [OWASP API Security API8:2023 - Security Misconfiguration](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [CWE-16: Configuration](https://cwe.mitre.org/data/definitions/16.html)
- [CAPEC-462: Cross-Domain Search Timing](https://capec.mitre.org/data/definitions/462.html)
- [SecurityHeaders.com](https://securityheaders.com/)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
