---
name: log-injection-anti-pattern
description: Security anti-pattern for log injection vulnerabilities (CWE-117). Use when generating or reviewing code that writes to log files, handles logging of user input, or processes log data. Detects unsanitized data in log messages enabling log forging and CRLF injection.
---

# Log Injection Anti-Pattern

**Severity:** Medium

## Risk

Log injection allows attackers to forge log entries, hide malicious activity, or exploit log viewers. This leads to:

- Forged audit trails
- Hidden attacks in log analysis
- Exploitation of log viewing tools
- CRLF injection creating fake entries

## BAD Pattern: Unsanitized User Input in Logs

```pseudocode
// VULNERABLE: User input directly in log message

FUNCTION login(request):
    username = request.body.username

    IF NOT authenticate(username, password):
        // Attacker: username = "admin\nLogin successful for admin"
        log.info("Login failed for user: " + username)
        RETURN {success: FALSE}
    END IF

    log.info("Login successful for user: " + username)
    RETURN {success: TRUE}
END FUNCTION

// Result in log file:
// Login failed for user: admin
// Login successful for admin
// (Attacker's injected line looks legitimate!)
```

## GOOD Pattern: Sanitized Logging

```pseudocode
// SECURE: Sanitize log data and use structured logging

FUNCTION sanitize_for_log(input):
    // Remove newlines and control characters
    result = input.replace("\n", "\\n")
    result = result.replace("\r", "\\r")
    result = result.replace("\t", "\\t")

    // Limit length
    IF result.length > 100:
        result = result.substring(0, 100) + "..."
    END IF

    RETURN result
END FUNCTION

FUNCTION login(request):
    username = request.body.username
    safe_username = sanitize_for_log(username)

    IF NOT authenticate(username, password):
        log.info("Login failed for user: " + safe_username)
        RETURN {success: FALSE}
    END IF

    log.info("Login successful for user: " + safe_username)
    RETURN {success: TRUE}
END FUNCTION
```

## GOOD Pattern: Structured Logging

```pseudocode
// BEST: Use structured logging (JSON format)

FUNCTION login(request):
    username = request.body.username

    IF NOT authenticate(username, password):
        // Structured logging prevents injection
        log.info("Login failed", {
            event: "login_failure",
            username: username,  // Properly escaped in JSON
            ip: request.client_ip,
            timestamp: current_timestamp()
        })
        RETURN {success: FALSE}
    END IF

    log.info("Login successful", {
        event: "login_success",
        username: username,
        ip: request.client_ip
    })
    RETURN {success: TRUE}
END FUNCTION

// JSON output:
// {"level":"info","message":"Login failed","event":"login_failure",
//  "username":"admin\nLogin successful for admin","ip":"..."}
// Newline is properly escaped as \n in JSON
```

## Characters to Sanitize

| Character | Escape To | Reason |
|-----------|-----------|--------|
| `\n` | `\\n` | Newline injection |
| `\r` | `\\r` | CRLF injection |
| `\t` | `\\t` | Format disruption |
| `<` | `&lt;` | HTML log viewers |
| `>` | `&gt;` | HTML log viewers |

## Detection

- Look for string concatenation in log statements
- Search for user input passed directly to log functions
- Check for missing sanitization of logged data
- Review logging configuration for format strings

## Prevention Checklist

- [ ] Sanitize all user input before logging
- [ ] Remove or escape newlines, carriage returns, and control characters
- [ ] Use structured logging (JSON) instead of text logs
- [ ] Limit logged data length to prevent DoS
- [ ] Never log sensitive data (passwords, tokens, PII)
- [ ] Use parameterized logging where available

## Related Patterns

- [xss](../xss/) - HTML injection in log viewers
- [missing-input-validation](../missing-input-validation/) - Root cause

## References

- [OWASP Top 10 A09:2025 - Security Logging and Alerting Failures](https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [CWE-117: Log Injection](https://cwe.mitre.org/data/definitions/117.html)
- [CAPEC-93: Log Injection-Tampering-Forging](https://capec.mitre.org/data/definitions/93.html)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
