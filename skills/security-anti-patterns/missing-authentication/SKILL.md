---
name: missing-authentication-anti-pattern
description: Security anti-pattern for missing or broken authentication (CWE-287). Use when generating or reviewing code for login systems, API endpoints, protected routes, or access control. Detects unprotected endpoints, weak password policies, and missing rate limiting on authentication.
---

# Missing Authentication Anti-Pattern

**Severity:** Critical

## Risk

Authentication failures are a leading cause of data breaches. AI-generated code often implements weak password policies, unprotected endpoints, and missing rate limiting learned from outdated tutorials. This leads to:

- Account takeover
- Unauthorized data access
- Credential stuffing attacks
- Brute force attacks

75.8% of developers believe AI-generated authentication code is secure (it often isn't).

## BAD Pattern: Unprotected Endpoints

```pseudocode
// VULNERABLE: Sensitive endpoint without authentication check

FUNCTION get_user_data(request):
    user_id = request.get_parameter("user_id")
    // No authentication check - anyone can access any user's data!
    user = database.get_user(user_id)
    RETURN user
END FUNCTION

FUNCTION admin_delete_user(request):
    // No check if requester is authenticated or authorized as admin
    user_id = request.get_parameter("user_id")
    database.delete_user(user_id)
    RETURN {success: TRUE}
END FUNCTION
```

## GOOD Pattern: Authentication Required

```pseudocode
// SECURE: All sensitive endpoints require authentication

FUNCTION get_user_data(request):
    // Verify authentication first
    current_user = authenticate_request(request)
    IF current_user IS NULL:
        RETURN error_response(401, "Authentication required")
    END IF

    user_id = request.get_parameter("user_id")

    // Authorization: Can this user access this data?
    IF current_user.id != user_id AND NOT current_user.is_admin:
        RETURN error_response(403, "Access denied")
    END IF

    user = database.get_user(user_id)
    RETURN user
END FUNCTION

FUNCTION admin_delete_user(request):
    current_user = authenticate_request(request)
    IF current_user IS NULL:
        RETURN error_response(401, "Authentication required")
    END IF

    IF NOT current_user.is_admin:
        RETURN error_response(403, "Admin access required")
    END IF

    user_id = request.get_parameter("user_id")
    database.delete_user(user_id)
    log.info("User deleted", {admin: current_user.id, deleted: user_id})
    RETURN {success: TRUE}
END FUNCTION
```

## BAD Pattern: Weak Password Requirements

```pseudocode
// VULNERABLE: No or weak password validation

FUNCTION register_user(username, password):
    IF password.length < 4:
        THROW Error("Password too short")
    END IF

    // No complexity, common password, or breach checks
    hash = md5(password)  // Weak hashing!
    database.insert("users", {username, password_hash: hash})
END FUNCTION
```

## GOOD Pattern: Strong Password Policy

```pseudocode
// SECURE: Strong password validation

FUNCTION register_user(username, password):
    validation = validate_password_strength(password)
    IF NOT validation.is_valid:
        THROW Error(validation.message)
    END IF

    hash = bcrypt.hash(password, rounds=12)
    database.insert("users", {username, password_hash: hash})
END FUNCTION

FUNCTION validate_password_strength(password):
    errors = []

    IF password.length < 12:
        errors.append("Password must be at least 12 characters")
    END IF

    IF NOT has_uppercase_lowercase_digit(password):
        errors.append("Password must contain uppercase, lowercase, and numbers")
    END IF

    IF is_common_password(password):
        errors.append("Password is too common")
    END IF

    IF is_breached_password(password):
        errors.append("Password found in data breach")
    END IF

    RETURN {is_valid: errors.length == 0, message: errors.join("; ")}
END FUNCTION
```

## BAD Pattern: No Rate Limiting

```pseudocode
// VULNERABLE: No rate limiting on authentication

FUNCTION login(username, password):
    user = database.find_user(username)
    IF user IS NULL OR NOT bcrypt.verify(password, user.password_hash):
        RETURN {success: FALSE, error: "Invalid credentials"}
    END IF
    RETURN {success: TRUE, token: generate_token(user)}
END FUNCTION

// Allows unlimited brute force and credential stuffing
```

## GOOD Pattern: Rate Limited Authentication

```pseudocode
// SECURE: Rate limiting with progressive delays

FUNCTION login(username, password):
    client_ip = request.get_client_ip()

    IF is_ip_rate_limited(client_ip):
        RETURN {success: FALSE, error: "Too many attempts, try again later"}
    END IF

    IF is_account_rate_limited(username):
        RETURN {success: FALSE, error: "Account temporarily locked"}
    END IF

    user = database.find_user(username)
    IF user IS NULL OR NOT bcrypt.verify(password, user.password_hash):
        record_failed_attempt(username, client_ip)
        RETURN {success: FALSE, error: "Invalid credentials"}
    END IF

    clear_failed_attempts(username, client_ip)
    RETURN {success: TRUE, token: generate_token(user)}
END FUNCTION
```

## Detection

- Look for endpoints without authentication middleware/decorators
- Search for database queries without prior auth checks
- Check for missing rate limiting on login/register endpoints
- Review password validation for minimum requirements

## Prevention Checklist

- [ ] All sensitive endpoints require authentication
- [ ] Implement strong password requirements (12+ chars, complexity)
- [ ] Check passwords against breached password lists
- [ ] Use bcrypt/argon2 for password hashing (never MD5/SHA1)
- [ ] Implement rate limiting on authentication endpoints
- [ ] Use constant-time comparison for credentials
- [ ] Log authentication events (without logging passwords)

## Related Patterns

- [session-fixation](../session-fixation/) - Session management issues
- [jwt-misuse](../jwt-misuse/) - Token-based authentication issues
- [missing-rate-limiting](../missing-rate-limiting/) - Broader rate limiting

## References

- [OWASP Top 10 A07:2021 - Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [CAPEC-115: Authentication Bypass](https://capec.mitre.org/data/definitions/115.html)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
