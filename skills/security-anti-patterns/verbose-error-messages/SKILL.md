---
name: verbose-error-messages-anti-pattern
description: Security anti-pattern for verbose error messages (CWE-209). Use when generating or reviewing code that handles errors, exceptions, or generates user-facing error responses. Detects stack trace exposure and detailed error information leakage to users.
---

# Verbose Error Messages Anti-Pattern

**Severity:** Medium

## Risk

Verbose error messages expose sensitive system information to attackers:

- Stack traces reveal file paths and code structure
- Database errors expose schema and query details
- Framework details assist targeted attacks
- Internal hostnames and IP addresses

## BAD Pattern: Raw Exceptions to Users

```pseudocode
// VULNERABLE: Full exception exposed to user

FUNCTION get_user(request):
    user_id = request.params.id

    TRY:
        user = database.query("SELECT * FROM users WHERE id = " + user_id)
        RETURN user
    CATCH Exception AS e:
        // Exposes SQL query, database structure, file paths
        RETURN error_response(500, str(e))
    END TRY
END FUNCTION

// Error response includes:
// "ProgrammingError: relation 'users' does not exist
//  File /app/src/handlers/user.py, line 42, in get_user
//  query = database.query(...)"
```

## GOOD Pattern: Generic External Errors

```pseudocode
// SECURE: Generic errors externally, detailed internally

FUNCTION get_user(request):
    user_id = request.params.id

    TRY:
        user = database.query("SELECT * FROM users WHERE id = ?", [user_id])
        RETURN user
    CATCH Exception AS e:
        // Log full details internally
        error_id = generate_error_id()
        log.error("Database error", {
            error_id: error_id,
            exception: str(e),
            stack_trace: e.stack_trace,
            user_id: user_id,
            request_id: request.id
        })

        // Return generic message to user
        RETURN error_response(500, {
            error: "An internal error occurred",
            error_id: error_id,  // For support reference
            message: "Please contact support if this persists"
        })
    END TRY
END FUNCTION
```

## BAD Pattern: Detailed Validation Errors

```pseudocode
// VULNERABLE: Too much detail in validation errors

FUNCTION login(request):
    username = request.body.username
    password = request.body.password

    user = database.find_user(username)

    IF user IS NULL:
        // Information disclosure: reveals username doesn't exist
        RETURN error_response(401, "User not found: " + username)
    END IF

    IF NOT bcrypt.verify(password, user.password_hash):
        // Information disclosure: confirms username exists
        RETURN error_response(401, "Incorrect password for user: " + username)
    END IF

    RETURN {success: TRUE}
END FUNCTION
```

## GOOD Pattern: Generic Authentication Errors

```pseudocode
// SECURE: Same error regardless of failure reason

FUNCTION login(request):
    username = request.body.username
    password = request.body.password

    user = database.find_user(username)

    // Same message for both "user not found" and "wrong password"
    IF user IS NULL OR NOT bcrypt.verify(password, user.password_hash):
        log.info("Login failed", {username: username})
        RETURN error_response(401, "Invalid credentials")
    END IF

    RETURN {success: TRUE}
END FUNCTION
```

## Error Message Guidelines

| Scenario | External Message | Internal Log |
|----------|------------------|--------------|
| Database error | "Service temporarily unavailable" | Full SQL error, query |
| File not found | "Resource not found" | Full path, permissions |
| Auth failure | "Invalid credentials" | Username, failure reason |
| Validation | Field-specific, no internals | Full validation details |

## Detection

- Search for `str(e)`, `e.message`, `e.stack_trace` in responses
- Look for exception handlers returning raw error data
- Check error responses for file paths or SQL queries
- Review authentication error messages for information leakage

## Prevention Checklist

- [ ] Return generic error messages to users
- [ ] Log detailed errors internally with correlation IDs
- [ ] Use consistent error messages for authentication failures
- [ ] Strip stack traces from production error responses
- [ ] Implement centralized error handling
- [ ] Include error IDs for customer support reference
- [ ] Review error messages for information disclosure

## Related Patterns

- [debug-mode-production](../debug-mode-production/) - Debug mode exposes detailed errors
- [missing-authentication](../missing-authentication/) - Auth error messages

## References

- [OWASP Top 10 A05:2021 - Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [OWASP Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)
- [CWE-209: Error Message Information Exposure](https://cwe.mitre.org/data/definitions/209.html)
- [CAPEC-54: Query System for Information](https://capec.mitre.org/data/definitions/54.html)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
