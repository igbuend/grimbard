---
name: hardcoded-secrets-anti-pattern
description: Security anti-pattern for hardcoded credentials and secrets (CWE-798). Use when generating or reviewing code that handles API keys, passwords, database credentials, encryption keys, or any sensitive configuration. Detects embedded secrets and recommends environment variables or secret managers.
---

# Hardcoded Secrets Anti-Pattern

**Severity:** Critical

## Risk

Secrets committed to version control are scraped within minutes by automated bots. AI frequently generates code with embedded credentials from tutorial examples in training data. This leads to:

- Cloud resource abuse (crypto mining, spam)
- Data breaches and exfiltration
- Account takeover
- Significant financial costs

Over 6 million secrets were detected on GitHub in 2023.

## BAD Pattern: Hardcoded API Keys and Passwords

```pseudocode
// VULNERABLE: Hardcoded API keys and passwords

CONSTANT API_KEY = "sk-abcd1234efgh5678ijkl9012mnop3456"
CONSTANT DB_PASSWORD = "super_secret_password"
CONSTANT AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
CONSTANT AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

FUNCTION call_api(endpoint):
    headers = {"Authorization": "Bearer " + API_KEY}
    RETURN http.get(endpoint, headers)
END FUNCTION
```

## GOOD Pattern: Environment Variables

```pseudocode
// SECURE: Environment variables

FUNCTION call_api(endpoint):
    api_key = environment.get("API_KEY")

    IF api_key IS NULL:
        THROW Error("API_KEY environment variable required")
    END IF

    headers = {"Authorization": "Bearer " + api_key}
    RETURN http.get(endpoint, headers)
END FUNCTION
```

## BAD Pattern: Credentials in Config Files

```pseudocode
// VULNERABLE: Credentials in config committed to repo
// config.json (tracked in git)
{
    "database_url": "postgresql://admin:password123@localhost:5432/mydb",
    "redis_password": "redis_secret_123"
}
```

## GOOD Pattern: External Secret Management

```pseudocode
// SECURE: Config without secrets
// config.json (safe to commit)
{
    "database_host": "localhost",
    "database_port": 5432,
    "database_name": "mydb"
}

FUNCTION connect_database():
    config = load_json("config.json")

    // Credentials from environment or secret manager
    db_user = environment.get("DB_USER")
    db_password = environment.get("DB_PASSWORD")

    IF db_user IS NULL OR db_password IS NULL:
        THROW Error("Database credentials not configured")
    END IF

    url = build_connection_url(config, db_user, db_password)
    RETURN database.connect(url)
END FUNCTION
```

## BAD Pattern: Secrets in Client-Side Code

```pseudocode
// VULNERABLE: Secrets exposed in frontend JavaScript
// frontend.js (served to browser)
CONSTANT STRIPE_SECRET_KEY = "sk_live_abc123..."  // Visible in DevTools!

FUNCTION charge_card(card_number, amount):
    RETURN http.post("https://api.stripe.com/charges", {
        api_key: STRIPE_SECRET_KEY,
        card: card_number,
        amount: amount
    })
END FUNCTION
```

## GOOD Pattern: Backend Proxy

```pseudocode
// SECURE: Backend proxy for sensitive operations
// frontend.js
FUNCTION charge_card(card_token, amount):
    // Only send public token, backend handles secret key
    RETURN http.post("/api/charges", {
        token: card_token,
        amount: amount
    })
END FUNCTION

// backend.js (server-side only)
FUNCTION handle_charge(request):
    stripe_key = environment.get("STRIPE_SECRET_KEY")
    RETURN stripe.charges.create({
        api_key: stripe_key,
        source: request.token,
        amount: request.amount
    })
END FUNCTION
```

## Detection

- Search for patterns: `password`, `secret`, `api_key`, `token`, `credential` in source code
- Look for base64-encoded strings that might be keys
- Check for AWS key patterns: `AKIA...`, `sk_live_`, `sk_test_`
- Review configuration files for embedded credentials
- Use secret scanning tools (gitleaks, trufflehog, git-secrets)

## Prevention Checklist

- [ ] Never hardcode credentials, API keys, or secrets in source code
- [ ] Use environment variables for all sensitive configuration
- [ ] Add secret patterns to `.gitignore` and pre-commit hooks
- [ ] Use a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.)
- [ ] Implement secret rotation capabilities
- [ ] Scan repositories for accidentally committed secrets

## Related Patterns

- [weak-encryption](../weak-encryption/) - Secrets need proper encryption at rest
- [jwt-misuse](../jwt-misuse/) - JWT secrets are often hardcoded
- [insufficient-randomness](../insufficient-randomness/) - Generating secure secrets

## References

- [OWASP Top 10 A07:2025 - Authentication Failures](https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [CAPEC-191: Read Sensitive Constants Within an Executable](https://capec.mitre.org/data/definitions/191.html)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
