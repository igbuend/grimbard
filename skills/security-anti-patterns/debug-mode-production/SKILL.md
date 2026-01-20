---
name: debug-mode-production-anti-pattern
description: Security anti-pattern for debug mode in production (CWE-215). Use when generating or reviewing code that configures application settings, deployment configurations, or error handling. Detects hardcoded debug flags and development-only features in production.
---

# Debug Mode in Production Anti-Pattern

**Severity:** High

## Risk

Debug mode in production exposes sensitive information and provides attack surface. This leads to:

- Exposure of stack traces with file paths
- Database query disclosure
- Environment variables and secrets leakage
- Source code exposure
- Increased attack surface via debug endpoints

## BAD Pattern: Hardcoded Debug Flag

```pseudocode
// VULNERABLE: Debug always enabled

CONSTANT DEBUG = TRUE  // Never changes between environments

FUNCTION start_application():
    app.config.debug = TRUE
    app.config.show_stack_traces = TRUE
    app.config.enable_profiler = TRUE

    // Exposes full stack traces, variable values, file paths
    app.run()
END FUNCTION

// Debug routes left in production
app.route("/debug/env", show_environment_variables)
app.route("/debug/config", show_all_config)
app.route("/debug/sql", run_arbitrary_sql)  // Catastrophic!
```

## GOOD Pattern: Environment-Based Configuration

```pseudocode
// SECURE: Configuration based on environment

FUNCTION get_config():
    environment = environment.get("APP_ENV", "production")

    IF environment == "production":
        RETURN {
            debug: FALSE,
            show_stack_traces: FALSE,
            log_level: "WARNING",
            enable_profiler: FALSE
        }
    ELSE IF environment == "development":
        RETURN {
            debug: TRUE,
            show_stack_traces: TRUE,
            log_level: "DEBUG",
            enable_profiler: TRUE
        }
    END IF
END FUNCTION

FUNCTION start_application():
    config = get_config()

    // Validate production settings
    IF environment.get("APP_ENV") == "production":
        IF config.debug == TRUE:
            log.error("CRITICAL: Debug mode enabled in production!")
            THROW ConfigurationError("Debug mode not allowed in production")
        END IF
    END IF

    app.config = config
    app.run()
END FUNCTION
```

## BAD Pattern: Debug Routes in Production

```pseudocode
// VULNERABLE: Debug endpoints accessible

// These routes should NEVER exist in production
app.route("/debug/env", FUNCTION():
    RETURN environment.get_all()  // Exposes all env vars!
END FUNCTION)

app.route("/_debug/sql", FUNCTION(request):
    query = request.body.query
    RETURN database.raw_query(query)  // SQL injection by design!
END FUNCTION)
```

## GOOD Pattern: Conditional Debug Routes

```pseudocode
// SECURE: Debug routes only in development

FUNCTION register_routes():
    // Normal routes always registered
    app.route("/api/users", handle_users)

    // Debug routes ONLY in development
    IF environment.get("APP_ENV") == "development":
        app.route("/debug/env", show_environment_variables)
        app.route("/debug/config", show_config)
    END IF

    // Additional: Protect any admin/debug routes
    IF has_debug_routes():
        log.warning("Debug routes registered - ensure not in production")
    END IF
END FUNCTION
```

## What Debug Mode Exposes

| Information | Risk |
|-------------|------|
| Stack traces | File paths, code structure |
| Database queries | Schema, data exposure |
| Environment variables | Secrets, API keys |
| Source code | Business logic, vulnerabilities |
| Session data | User information, tokens |

## Detection

- Search for `DEBUG = True` or `debug: true` in code
- Look for `/debug/`, `/_debug/`, `/admin/debug` routes
- Check for development dependencies in production builds
- Review error handling for stack trace exposure

## Prevention Checklist

- [ ] Use environment variables for debug configuration
- [ ] Never hardcode DEBUG = TRUE
- [ ] Remove debug routes before deployment
- [ ] Exclude development dependencies from production builds
- [ ] Implement startup checks that fail on debug mode in production
- [ ] Use separate configuration files for each environment
- [ ] Review CI/CD pipeline for environment variable injection

## Related Patterns

- [verbose-error-messages](../verbose-error-messages/) - Related information disclosure
- [hardcoded-secrets](../hardcoded-secrets/) - Often exposed by debug mode
- [missing-security-headers](../missing-security-headers/) - Defense in depth

## References

- [OWASP Top 10 A05:2021 - Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [CWE-215: Debug Information Exposure](https://cwe.mitre.org/data/definitions/215.html)
- [CAPEC-121: Exploit Non-Production Interfaces](https://capec.mitre.org/data/definitions/121.html)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
