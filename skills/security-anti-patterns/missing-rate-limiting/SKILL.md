---
name: missing-rate-limiting-anti-pattern
description: Security anti-pattern for missing rate limiting (CWE-770). Use when generating or reviewing API endpoints, authentication systems, or public-facing services. Detects absence of request throttling enabling brute force, credential stuffing, and DoS attacks.
---

# Missing Rate Limiting Anti-Pattern

**Severity:** High

## Risk

Missing rate limiting allows attackers to abuse endpoints without restriction:

- Brute force password attacks
- Credential stuffing
- API abuse and scraping
- Denial of service
- Resource exhaustion

## BAD Pattern: No Rate Limiting

```pseudocode
// VULNERABLE: Unlimited requests allowed

FUNCTION login(request):
    username = request.body.username
    password = request.body.password

    // No rate limiting - attackers can try unlimited passwords
    user = database.find_user(username)
    IF user AND bcrypt.verify(password, user.password_hash):
        RETURN {success: TRUE, token: generate_token(user)}
    END IF

    RETURN {success: FALSE, error: "Invalid credentials"}
END FUNCTION

FUNCTION api_search(request):
    query = request.params.q

    // No rate limiting - enables scraping and DoS
    results = database.search(query)
    RETURN results
END FUNCTION
```

## GOOD Pattern: IP and Account Rate Limiting

```pseudocode
// SECURE: Multiple rate limiting layers

FUNCTION login(request):
    client_ip = request.get_client_ip()
    username = request.body.username

    // Layer 1: IP-based rate limiting
    IF is_ip_rate_limited(client_ip, limit=10, window=900):
        log.warning("IP rate limited", {ip: client_ip})
        RETURN error_response(429, "Too many attempts, try again later")
    END IF

    // Layer 2: Account-based rate limiting
    IF is_account_rate_limited(username, limit=5, window=300):
        log.warning("Account rate limited", {username: username})
        RETURN error_response(429, "Account temporarily locked")
    END IF

    user = database.find_user(username)
    IF user IS NULL OR NOT bcrypt.verify(password, user.password_hash):
        record_failed_attempt(client_ip, username)
        RETURN {success: FALSE, error: "Invalid credentials"}
    END IF

    clear_rate_limit(client_ip, username)
    RETURN {success: TRUE, token: generate_token(user)}
END FUNCTION

// Rate limiting implementation
FUNCTION is_ip_rate_limited(ip, limit, window):
    key = "rate_limit:ip:" + ip
    count = redis.incr(key)

    IF count == 1:
        redis.expire(key, window)
    END IF

    RETURN count > limit
END FUNCTION
```

## Rate Limiting Algorithms

| Algorithm | Description | Use Case |
|-----------|-------------|----------|
| Fixed Window | Count per time window | Simple, memory efficient |
| Sliding Window | Smooth rate over time | More accurate |
| Token Bucket | Burst + sustained rate | API rate limiting |
| Leaky Bucket | Constant output rate | Traffic smoothing |

## Common Rate Limits

| Endpoint | Suggested Limit |
|----------|-----------------|
| Login | 5-10 per 15 minutes per IP |
| Password reset | 3 per hour per email |
| API calls | 100-1000 per hour per key |
| Registration | 5 per hour per IP |
| File upload | 10 per hour per user |

## Detection

- Look for endpoints without rate limiting middleware
- Search for authentication code without attempt tracking
- Check for APIs without request quotas
- Review for missing 429 (Too Many Requests) responses

## Prevention Checklist

- [ ] Implement IP-based rate limiting for all public endpoints
- [ ] Add account-based rate limiting for authentication
- [ ] Use progressive delays/lockouts for repeated failures
- [ ] Set API quotas based on authentication level
- [ ] Return 429 status code with Retry-After header
- [ ] Log rate limit violations for security monitoring
- [ ] Consider CAPTCHA after rate limit threshold

## Response Headers

```pseudocode
// Include rate limit information in responses

FUNCTION add_rate_limit_headers(response, limit, remaining, reset):
    response.set_header("X-RateLimit-Limit", limit)
    response.set_header("X-RateLimit-Remaining", remaining)
    response.set_header("X-RateLimit-Reset", reset)

    IF remaining == 0:
        response.set_header("Retry-After", reset - current_time())
    END IF
END FUNCTION
```

## Related Patterns

- [missing-authentication](../missing-authentication/) - Auth-specific rate limiting
- [missing-input-validation](../missing-input-validation/) - Input size limits

## References

- [OWASP Top 10 A06:2025 - Insecure Design](https://owasp.org/Top10/2025/A06_2025-Insecure_Design/)
- [OWASP API Security API4:2023 - Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)
- [OWASP Rate Limiting](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
- [CWE-770: Resource Allocation Without Limits](https://cwe.mitre.org/data/definitions/770.html)
- [CAPEC-49: Password Brute Forcing](https://capec.mitre.org/data/definitions/49.html)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
