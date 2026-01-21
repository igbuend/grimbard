---
name: open-cors-anti-pattern
description: Security anti-pattern for overly permissive CORS (CWE-346). Use when generating or reviewing code that configures CORS headers, handles cross-origin requests, or sets up API access policies. Detects wildcard origins and credential exposure risks.
---

# Open CORS Anti-Pattern

**Severity:** Medium

## Risk

Overly permissive CORS allows malicious websites to make authenticated requests to your API:

- Cross-site data theft
- CSRF-like attacks
- Credential leakage
- Session hijacking via JavaScript

## BAD Pattern: Wildcard CORS

```pseudocode
// VULNERABLE: Allows any origin

FUNCTION configure_cors():
    // Allows ANY website to make requests
    server.set_header("Access-Control-Allow-Origin", "*")
    server.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
    server.set_header("Access-Control-Allow-Headers", "*")
END FUNCTION

// Problem: evil.com can now call your API from user's browser
```

## BAD Pattern: Credentials with Wildcard

```pseudocode
// VULNERABLE: Wildcard with credentials (browser will reject, but shows misunderstanding)

FUNCTION configure_cors_broken():
    // This combination is invalid and dangerous intent
    server.set_header("Access-Control-Allow-Origin", "*")
    server.set_header("Access-Control-Allow-Credentials", "true")

    // If you "fix" by reflecting origin, you create a bigger problem
END FUNCTION
```

## BAD Pattern: Reflecting Origin Without Validation

```pseudocode
// VULNERABLE: Reflects any origin - same as wildcard but allows credentials

FUNCTION handle_request(request):
    origin = request.get_header("Origin")

    // Reflects whatever origin is sent - allows ANY site
    response.set_header("Access-Control-Allow-Origin", origin)
    response.set_header("Access-Control-Allow-Credentials", "true")

    // evil.com can now make authenticated requests!
END FUNCTION
```

## GOOD Pattern: Allowlist of Origins

```pseudocode
// SECURE: Only allow specific trusted origins

CONSTANT ALLOWED_ORIGINS = [
    "https://myapp.com",
    "https://www.myapp.com",
    "https://admin.myapp.com"
]

FUNCTION handle_cors(request, response):
    origin = request.get_header("Origin")

    IF origin IN ALLOWED_ORIGINS:
        response.set_header("Access-Control-Allow-Origin", origin)
        response.set_header("Access-Control-Allow-Credentials", "true")
        response.set_header("Access-Control-Allow-Methods", "GET, POST, PUT")
        response.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        response.set_header("Access-Control-Max-Age", "86400")
    END IF

    // If origin not in allowlist, don't set CORS headers
    // Browser will block the request
END FUNCTION

// Handle preflight OPTIONS requests
FUNCTION handle_preflight(request, response):
    origin = request.get_header("Origin")

    IF origin IN ALLOWED_ORIGINS:
        response.set_header("Access-Control-Allow-Origin", origin)
        response.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
        response.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        response.set_header("Access-Control-Max-Age", "86400")
        RETURN response_with_status(204)
    END IF

    RETURN response_with_status(403)
END FUNCTION
```

## GOOD Pattern: Dynamic Origin Validation

```pseudocode
// SECURE: Validate origin against patterns

FUNCTION is_valid_origin(origin):
    IF origin IS NULL:
        RETURN FALSE
    END IF

    // Parse origin
    TRY:
        parsed = url_parse(origin)
    CATCH:
        RETURN FALSE
    END TRY

    // Must be HTTPS in production
    IF environment == "production" AND parsed.protocol != "https:":
        RETURN FALSE
    END IF

    // Check against allowed domains
    allowed_domains = ["myapp.com", "mycompany.com"]

    FOR domain IN allowed_domains:
        IF parsed.host == domain OR parsed.host.ends_with("." + domain):
            RETURN TRUE
        END IF
    END FOR

    RETURN FALSE
END FUNCTION
```

## CORS Headers Reference

| Header | Purpose | Secure Value |
|--------|---------|--------------|
| `Access-Control-Allow-Origin` | Allowed origins | Specific origin, not `*` |
| `Access-Control-Allow-Credentials` | Allow cookies | `true` only with specific origin |
| `Access-Control-Allow-Methods` | Allowed methods | Only needed methods |
| `Access-Control-Allow-Headers` | Allowed headers | Specific list |
| `Access-Control-Max-Age` | Preflight cache | `86400` (24 hours) |

## Detection

- Search for `Access-Control-Allow-Origin: *`
- Look for origin reflection without validation
- Check for credentials enabled with permissive origins
- Review CORS middleware configuration

## Prevention Checklist

- [ ] Use explicit allowlist of trusted origins
- [ ] Never use wildcard `*` with credentials
- [ ] Validate origins against allowlist, not blocklist
- [ ] Use HTTPS for all allowed origins in production
- [ ] Restrict allowed methods to what's needed
- [ ] Set reasonable preflight cache duration
- [ ] Log rejected CORS requests for monitoring

## Related Patterns

- [missing-security-headers](../missing-security-headers/) - Related header configuration
- [missing-authentication](../missing-authentication/) - CORS with auth

## References

- [OWASP Top 10 A02:2025 - Security Misconfiguration](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/)
- [CWE-346: Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)
- [CAPEC-111: JSON Hijacking](https://capec.mitre.org/data/definitions/111.html)
- [MDN: CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
