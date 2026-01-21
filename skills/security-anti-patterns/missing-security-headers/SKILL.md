---
name: missing-security-headers-anti-pattern
description: Security anti-pattern for missing security headers (CWE-16). Use when generating or reviewing web application code, server configuration, or HTTP response handling. Detects missing CSP, HSTS, X-Frame-Options, and other protective headers.
---

# Missing Security Headers Anti-Pattern

**Severity:** Medium

## Risk

Missing security headers leave web applications vulnerable to various attacks:

- XSS exploitation without CSP
- Clickjacking via iframe embedding
- Man-in-the-middle attacks without HSTS
- MIME type sniffing attacks
- Information disclosure via headers

## BAD Pattern: No Security Headers

```pseudocode
// VULNERABLE: No security headers configured

FUNCTION configure_server():
    // No security headers set - browser uses defaults
    server.start()
END FUNCTION

FUNCTION handle_request(request):
    response = generate_response(request)
    // Returns response without protective headers
    RETURN response
END FUNCTION
```

## GOOD Pattern: Comprehensive Security Headers

```pseudocode
// SECURE: All recommended security headers

FUNCTION configure_server():
    // Content Security Policy - prevents XSS
    server.set_header("Content-Security-Policy",
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data: https:; " +
        "font-src 'self'; " +
        "connect-src 'self'; " +
        "frame-ancestors 'none'; " +
        "base-uri 'self'; " +
        "form-action 'self'"
    )

    // Prevent clickjacking
    server.set_header("X-Frame-Options", "DENY")

    // Force HTTPS
    server.set_header("Strict-Transport-Security",
        "max-age=31536000; includeSubDomains; preload")

    // Prevent MIME type sniffing
    server.set_header("X-Content-Type-Options", "nosniff")

    // Control referrer information
    server.set_header("Referrer-Policy", "strict-origin-when-cross-origin")

    // Permissions policy (feature policy)
    server.set_header("Permissions-Policy",
        "geolocation=(), microphone=(), camera=()")

    server.start()
END FUNCTION
```

## Essential Security Headers

| Header | Purpose | Example |
|--------|---------|---------|
| `Content-Security-Policy` | Prevent XSS | `default-src 'self'` |
| `X-Frame-Options` | Prevent clickjacking | `DENY` |
| `Strict-Transport-Security` | Force HTTPS | `max-age=31536000` |
| `X-Content-Type-Options` | Prevent MIME sniffing | `nosniff` |
| `Referrer-Policy` | Control referrer leakage | `strict-origin` |
| `Permissions-Policy` | Disable browser features | `geolocation=()` |

## Content-Security-Policy Examples

```pseudocode
// Strict CSP (recommended)
csp = "default-src 'self'; script-src 'self'; style-src 'self'"

// CSP with nonces for inline scripts
FUNCTION render_with_csp_nonce():
    nonce = crypto.random_bytes(16).to_base64()

    response.set_header("Content-Security-Policy",
        "script-src 'self' 'nonce-" + nonce + "'"
    )

    html = "<script nonce='" + nonce + "'>...</script>"
    RETURN html
END FUNCTION

// Report-only mode for testing
server.set_header("Content-Security-Policy-Report-Only",
    "default-src 'self'; report-uri /csp-report")
```

## Detection

- Use browser DevTools to inspect response headers
- Run security header scanners (securityheaders.com)
- Search for response handling code missing header configuration
- Review web server configuration files

## Prevention Checklist

- [ ] Set Content-Security-Policy to restrict resource loading
- [ ] Add X-Frame-Options: DENY or SAMEORIGIN
- [ ] Enable HSTS with long max-age (1 year minimum)
- [ ] Set X-Content-Type-Options: nosniff
- [ ] Configure appropriate Referrer-Policy
- [ ] Use Permissions-Policy to disable unused browser features
- [ ] Test headers with online scanners
- [ ] Consider HSTS preload submission

## Framework-Specific Examples

```pseudocode
// Express.js (use helmet middleware)
app.use(helmet())

// Django
SECURE_BROWSER_XSS_FILTER = TRUE
X_FRAME_OPTIONS = 'DENY'
SECURE_CONTENT_TYPE_NOSNIFF = TRUE
SECURE_HSTS_SECONDS = 31536000

// Flask
response.headers['X-Frame-Options'] = 'DENY'
response.headers['Content-Security-Policy'] = "default-src 'self'"
```

## Related Patterns

- [xss](../xss/) - CSP provides defense in depth
- [open-cors](../open-cors/) - Related header misconfiguration

## References

- [OWASP Top 10 A02:2025 - Security Misconfiguration](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/)
- [OWASP API Security API8:2023 - Security Misconfiguration](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [CWE-16: Configuration](https://cwe.mitre.org/data/definitions/16.html)
- [CAPEC-462: Cross-Domain Search Timing](https://capec.mitre.org/data/definitions/462.html)
- [SecurityHeaders.com](https://securityheaders.com/)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
