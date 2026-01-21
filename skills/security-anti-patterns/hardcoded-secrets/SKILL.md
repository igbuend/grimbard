---
name: "hardcoded-secrets-anti-pattern"
description: "Security anti-pattern for hardcoded credentials and secrets (CWE-798). Use when generating or reviewing code that handles API keys, passwords, database credentials, encryption keys, or any sensitive configuration. Detects embedded secrets and recommends environment variables or secret managers."
---

# Hardcoded Secrets Anti-Pattern

**Severity:** Critical

## Summary
Hardcoding secrets is the practice of embedding sensitive information, such as API keys, passwords, or database credentials, directly into the source code. This is a critical vulnerability because anyone with access to the code—including developers, version control history, or attackers who gain source code access—can see the secret. AI models frequently generate code with hardcoded secrets, as they are trained on vast amounts of public code from tutorials and examples where this bad practice is common. Secrets committed to a public repository are often discovered and abused by automated bots within minutes.

## The Anti-Pattern
The anti-pattern is storing any form of secret, credential, or sensitive configuration value directly in a file that is tracked by version control.

### BAD Code Example
```python
# VULNERABLE: Hardcoded API keys and database credentials in the source code.
import requests
import psycopg2

# 1. Hardcoded API Key
API_KEY = "sk-live-123abc456def789ghi"

def get_weather(city):
    url = f"https://api.weatherprovider.com/v1/current?city={city}"
    headers = {"Authorization": f"Bearer {API_KEY}"}
    response = requests.get(url, headers=headers)
    return response.json()

# 2. Hardcoded Database Password
DB_HOST = "localhost"
DB_USER = "admin"
DB_PASSWORD = "my_super_secret_password_123" # Exposed in the code
DB_NAME = "main_db"

def get_db_connection():
    # The password is right here for any attacker to see.
    conn = psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )
    return conn
```

### GOOD Code Example
```python
# SECURE: Load secrets from the environment or a dedicated secrets manager.
import os
import requests
import psycopg2

# 1. API key loaded from an environment variable.
API_KEY = os.environ.get("WEATHER_API_KEY")

def get_weather(city):
    if not API_KEY:
        raise ValueError("WEATHER_API_KEY environment variable not set.")
    url = f"https://api.weatherprovider.com/v1/current?city={city}"
    headers = {"Authorization": f"Bearer {API_KEY}"}
    response = requests.get(url, headers=headers)
    return response.json()

# 2. Database credentials loaded from environment variables.
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_USER = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
DB_NAME = os.environ.get("DB_NAME")

def get_db_connection():
    # The application will fail safely if secrets are not configured in the environment.
    if not all([DB_USER, DB_PASSWORD, DB_NAME]):
        raise ValueError("Database environment variables are not fully configured.")
    conn = psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )
    return conn
```

## Detection
- **Use secret scanning tools:** Tools like `gitleaks`, `trufflehog`, or `git-secrets` can automatically scan your repository's history for patterns that match common secret formats.
- **Search for keywords:** Manually search the codebase for keywords like `password`, `secret`, `api_key`, `token`, and `credential`.
- **Look for high-entropy strings:** Long, random-looking strings are often API keys or private keys.
- **Check configuration files:** Review files like `config.json`, `settings.py`, or `.env` files that have been committed to version control.

## Prevention
- [ ] **Never hardcode any credentials, API keys, or secrets** in your source code.
- [ ] **Use environment variables** to store secrets in development and other non-production environments.
- [ ] **Use a dedicated secrets management service** for production environments (e.g., AWS Secrets Manager, HashiCorp Vault, Google Secret Manager).
- [ ] **Add a `.env` file** (or similar) to your `.gitignore` to prevent accidental commits of local development secrets.
- [ ] **Integrate secret scanning tools** into your CI/CD pipeline and pre-commit hooks to block commits that contain secrets.
- [ ] **Implement a secret rotation policy** to limit the impact of a compromised secret.

## Related Security Patterns & Anti-Patterns
- [Weak Encryption Anti-Pattern](../weak-encryption/): Secrets, even when stored, need to be encrypted at rest.
- [JWT Misuse Anti-Pattern](../jwt-misuse/): The secret key for signing JWTs is a common hardcoded secret.
- [Verbose Error Messages Anti-Pattern](../verbose-error-messages/): Debug screens can leak environment variables, which may contain secrets.

## References
- [OWASP Top 10 A07:2025 - Authentication Failures](https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/)
- [OWASP GenAI LLM02:2025 - Sensitive Information Disclosure](https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/)
- [OWASP API Security API2:2023 - Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [CAPEC-191: Read Sensitive Constants Within an Executable](https://capec.mitre.org/data/definitions/191.html)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
