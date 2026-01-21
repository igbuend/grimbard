---
name: "debug-mode-production-anti-pattern"
description: "Security anti-pattern for debug mode in production (CWE-215). Use when generating or reviewing code that configures application settings, deployment configurations, or error handling. Detects hardcoded debug flags and development-only features in production."
---

# Debug Mode in Production Anti-Pattern

**Severity:** High

## Summary
Enabling debug mode in a production environment is a critical security misconfiguration. This anti-pattern occurs when development settings or debugging features are not disabled before deployment, exposing sensitive system information and creating unintended backdoors. AI-generated code can inadvertently include hardcoded debug flags or fail to differentiate between production and development environments, leading to this vulnerability.

## The Anti-Pattern
This anti-pattern manifests in two primary ways:
1.  **Hardcoded Debug Flags:** A global flag like `DEBUG = True` is set in the code and is never changed, meaning the application runs in debug mode in all environments.
2.  **Unprotected Debug Endpoints:** Routes or endpoints intended for debugging (e.g., `/debug/env`, `/_debug/sql`) are included in the production build, providing a powerful vector for attackers.

### BAD Code Example
```python
# VULNERABLE: Hardcoded debug flag and unprotected debug routes
import os
from flask import Flask, jsonify

app = Flask(__name__)
app.config['DEBUG'] = True # Hardcoded debug mode

@app.route("/")
def index():
    return "Welcome!"

# This debug route exposes all environment variables, including potential secrets.
# It should never be present in a production environment.
@app.route("/debug/env")
def debug_env():
    if app.config['DEBUG']:
        return jsonify(os.environ.copy())
    return "Not in debug mode."

if __name__ == "__main__":
    app.run()
```

### GOOD Code Example
```python
# SECURE: Environment-based configuration and conditional routes
import os
from flask import Flask, jsonify

app = Flask(__name__)

# Load configuration from the environment. Default to 'production'.
APP_ENV = os.environ.get('APP_ENV', 'production')
app.config['DEBUG'] = APP_ENV == 'development'

@app.route("/")
def index():
    return "Welcome!"

# This debug route is now conditionally registered and will only exist
# if the application is explicitly run in a development environment.
if app.config['DEBUG']:
    @app.route("/debug/env")
    def debug_env():
        return jsonify(os.environ.copy())

# It's also a good practice to add a startup check to prevent accidental
# deployment of debug mode to production.
if APP_ENV == 'production' and app.config['DEBUG']:
    raise ValueError("FATAL: Debug mode is enabled in a production environment. Aborting.")

if __name__ == "__main__":
    app.run()

```

## Detection
- Search for hardcoded debug flags like `DEBUG = True` or `debug: true` in configuration files and source code.
- Look for routes or endpoints with names like `/debug`, `/_debug`, or `/admin/debug`.
- Check for the presence of development-only dependencies or packages in the production build.
- Review error handling logic to see if it exposes detailed stack traces or sensitive information to the user.

## Prevention
- [ ] **Use environment variables** to control debug mode and other environment-specific settings.
- [ ] **Never hardcode `DEBUG = True`**.
- [ ] **Conditionally register debug routes** so they are not included in production builds.
- [ ] **Implement a startup check** in the application that aborts if it detects debug mode is enabled in a production environment.
- [ ] **Use separate configuration files** for each environment (development, staging, production) to avoid overlap.
- [ ] **Review your CI/CD pipeline** to ensure that the correct environment variables are being injected and that development artifacts are excluded from the final build.

## Related Security Patterns & Anti-Patterns
- [Verbose Error Messages Anti-Pattern](../verbose-error-messages/): A common consequence of running in debug mode.
- [Hardcoded Secrets Anti-Pattern](../hardcoded-secrets/): Secrets are often exposed through debug information.
- [Missing Security Headers Anti-Pattern](../missing-security-headers/): Can provide defense-in-depth by controlling how browsers handle content.

## References
- [OWASP Top 10 A02:2025 - Security Misconfiguration](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/)
- [OWASP GenAI LLM02:2025 - Sensitive Information Disclosure](https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/)
- [OWASP API Security API8:2023 - Security Misconfiguration](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/)
- [CWE-215: Debug Information Exposure](https://cwe.mitre.org/data/definitions/215.html)
- [CAPEC-121: Exploit Non-Production Interfaces](https://capec.mitre.org/data/definitions/121.html)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
