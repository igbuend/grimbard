---
name: insecure-defaults
description: Security anti-pattern for fail-open defaults (CWE-1188). Use when reviewing code that uses fallback values for secrets, credentials, or security settings. Detects applications that run with weak defaults when configuration is missing.
aliases:
  - fail-open
  - default-secrets
---

# Insecure Defaults Anti-Pattern

**Severity:** Critical

## Summary

Insecure defaults occur when applications continue operating with weak or default values when required configuration is missing. Unlike hardcoded secrets (which are always present), insecure defaults create fail-open conditions where missing environment variables cause the application to silently use unsafe fallback values. This is particularly dangerous because the vulnerability only manifests in misconfigured deployments.

## The Anti-Pattern

Never provide fallback values for security-critical configuration. Applications should fail immediately (fail-secure) when required secrets or security settings are missing.

### Key Distinction

| Pattern | Behavior | Risk |
|---------|----------|------|
| **Fail-open (BAD)** | Uses default when config missing | Silent security bypass |
| **Fail-secure (GOOD)** | Crashes when config missing | Deployment fails safely |

### BAD Code Examples

```python
# VULNERABLE: Fail-open - application runs with weak defaults
import os
import jwt

# 1. Default secret when environment variable is missing
SECRET_KEY = os.environ.get("SECRET_KEY", "default-secret-change-me")

# 2. Debug mode defaults to enabled
DEBUG = os.environ.get("DEBUG", "true").lower() == "true"

# 3. Weak algorithm fallback
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")  # Should require RS256

def create_token(user_id):
    # Runs with weak secret if SECRET_KEY not set
    return jwt.encode({"user_id": user_id}, SECRET_KEY, algorithm=JWT_ALGORITHM)

def verify_token(token):
    # Attacker can forge tokens using "default-secret-change-me"
    return jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
```

```javascript
// VULNERABLE: Node.js fail-open patterns
const express = require('express');
const session = require('express-session');

const app = express();

// 1. Session secret with insecure default
app.use(session({
  secret: process.env.SESSION_SECRET || 'keyboard cat',  // Fail-open!
  resave: false,
  saveUninitialized: true
}));

// 2. CORS defaults to permissive
const corsOrigin = process.env.CORS_ORIGIN || '*';  // Allows all origins!

// 3. Rate limiting disabled by default
const rateLimit = process.env.RATE_LIMIT || 0;  // 0 = unlimited
```

### GOOD Code Examples

```python
# SECURE: Fail-secure - application crashes if config missing
import os
import sys
import jwt

def get_required_env(name):
    """Get required environment variable or exit."""
    value = os.environ.get(name)
    if not value:
        sys.exit(f"FATAL: Required environment variable {name} is not set")
    return value

# 1. No default - must be configured
SECRET_KEY = get_required_env("SECRET_KEY")

# 2. Debug defaults to disabled (safe default)
DEBUG = os.environ.get("DEBUG", "false").lower() == "true"

# 3. Validate algorithm is secure
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "RS256")
if JWT_ALGORITHM not in ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]:
    sys.exit(f"FATAL: Insecure JWT algorithm: {JWT_ALGORITHM}")

def create_token(user_id):
    return jwt.encode({"user_id": user_id}, SECRET_KEY, algorithm=JWT_ALGORITHM)
```

```javascript
// SECURE: Node.js fail-secure patterns
const express = require('express');
const session = require('express-session');

function requireEnv(name) {
  const value = process.env[name];
  if (!value) {
    console.error(`FATAL: Required environment variable ${name} is not set`);
    process.exit(1);
  }
  return value;
}

const app = express();

// 1. Session secret required - no default
app.use(session({
  secret: requireEnv('SESSION_SECRET'),
  resave: false,
  saveUninitialized: false,  // Also secure default
  cookie: { secure: true }   // Require HTTPS
}));

// 2. CORS must be explicitly configured
const corsOrigin = requireEnv('CORS_ORIGIN');
if (corsOrigin === '*') {
  console.error('FATAL: CORS_ORIGIN cannot be wildcard in production');
  process.exit(1);
}

// 3. Rate limiting with secure default
const rateLimit = parseInt(process.env.RATE_LIMIT || '100', 10);
```

### Language-Specific Examples

**Go:**
```go
// VULNERABLE: Fail-open defaults
func getConfig() Config {
    return Config{
        // Default secret if not set
        JWTSecret:  getEnvOrDefault("JWT_SECRET", "development-secret"),
        // Debug enabled by default
        Debug:      getEnvOrDefault("DEBUG", "true") == "true",
        // Permissive CORS
        CORSOrigin: getEnvOrDefault("CORS_ORIGIN", "*"),
    }
}
```

```go
// SECURE: Fail-secure - panic on missing required config
func getConfig() Config {
    jwtSecret := os.Getenv("JWT_SECRET")
    if jwtSecret == "" {
        log.Fatal("FATAL: JWT_SECRET environment variable required")
    }

    corsOrigin := os.Getenv("CORS_ORIGIN")
    if corsOrigin == "" || corsOrigin == "*" {
        log.Fatal("FATAL: CORS_ORIGIN must be explicitly set (not wildcard)")
    }

    return Config{
        JWTSecret:  jwtSecret,
        Debug:      os.Getenv("DEBUG") == "true",  // Defaults to false
        CORSOrigin: corsOrigin,
    }
}
```

**Java/Spring Boot:**
```java
// VULNERABLE: application.properties with insecure defaults
// jwt.secret=${JWT_SECRET:default-secret-do-not-use}
// cors.allowed-origins=${CORS_ORIGINS:*}
// debug.enabled=${DEBUG:true}
```

```java
// SECURE: Require configuration, no insecure defaults
@Configuration
public class SecurityConfig {

    @Value("${jwt.secret}")  // No default - fails if missing
    private String jwtSecret;

    @Value("${cors.allowed-origins}")  // No default
    private String corsOrigins;

    @PostConstruct
    public void validateConfig() {
        if (jwtSecret == null || jwtSecret.length() < 32) {
            throw new IllegalStateException("jwt.secret must be at least 32 characters");
        }
        if ("*".equals(corsOrigins)) {
            throw new IllegalStateException("cors.allowed-origins cannot be wildcard");
        }
    }
}
```

## Detection

Search for fallback patterns in configuration code:

```bash
# Python: os.environ.get with default values for secrets
rg 'environ\.get\([^)]+,\s*["\'][^"\']+["\']' --type py

# JavaScript: process.env with || fallback
rg 'process\.env\.\w+\s*\|\|' --type js --type ts

# Go: getEnvOrDefault patterns
rg 'getEnv.*Default|Getenv.*""' --type go

# Generic: Common insecure default strings
rg -i '(secret|key|password|token).*default|change.?me|keyboard.?cat|development'
```

### What to Ignore (Not Vulnerabilities)

- Test directories and spec files
- Example/sample/template files
- Development-only configurations (docker-compose.dev.yml)
- Documentation and README files
- Build-time placeholders replaced during deployment
- Fail-secure patterns that crash on missing config

## Prevention

- [ ] **Never provide defaults for secrets** - API keys, passwords, signing keys must be explicitly configured
- [ ] **Fail-secure on startup** - Crash immediately if required configuration is missing
- [ ] **Default security settings to restrictive** - Debug=false, CORS=specific origins, rate limiting=enabled
- [ ] **Validate configuration at startup** - Check for weak values, not just missing values
- [ ] **Use schema validation** - Validate all config against expected types and constraints
- [ ] **Separate dev/prod configs** - Never share configuration between environments

## Related Anti-Patterns

- [Hardcoded Secrets](../hardcoded-secrets/): Secrets embedded in code vs. insecure fallback defaults
- [Debug Mode in Production](../debug-mode-production/): Debug=true as insecure default
- [Missing Authentication](../missing-authentication/): Auth disabled by default
- [Open CORS](../open-cors/): CORS=* as insecure default

## References

- [CWE-1188: Initialization with Hard-Coded Network Resource Configuration Data](https://cwe.mitre.org/data/definitions/1188.html)
- [CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)
- [CWE-276: Incorrect Default Permissions](https://cwe.mitre.org/data/definitions/276.html)
- [CAPEC-121: Exploit Non-Production Interfaces](https://capec.mitre.org/data/definitions/121.html)
- [OWASP Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [OWASP API Security API8:2023 - Security Misconfiguration](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- Source: Modified from [Trail of Bits Skills](https://github.com/trailofbits/skills) (CC BY-SA 4.0)
