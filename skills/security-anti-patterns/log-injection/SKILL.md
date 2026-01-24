---
name: "log-injection-anti-pattern"
description: "Security anti-pattern for log injection vulnerabilities (CWE-117). Use when generating or reviewing code that writes to log files, handles logging of user input, or processes log data. Detects unsanitized data in log messages enabling log forging and CRLF injection."
---

# Log Injection Anti-Pattern

**Severity:** Medium

## Summary

Log injection occurs when attackers write arbitrary data into log files by injecting newlines (\n) and carriage returns (\r) through unsanitized user input. Attackers create fake log entries to hide malicious activity, mislead administrators, and exploit log analysis tools.

## The Anti-Pattern

Never log unsanitized user input. Attackers inject newline characters to forge log entries.

### BAD Code Example

```python
# VULNERABLE: User input is logged directly without sanitization.
import logging

logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def user_login(username, ip_address):
    # An attacker can provide a username that contains a newline character.
    # Example: "j_smith\nINFO - Successful login for user: admin from IP: 10.0.0.1"
    logging.info(f"Failed login attempt for user: {username} from IP: {ip_address}")

# Attacker's input:
# username = "j_smith\nINFO - 2023-10-27 10:00:00,000 - Successful login for user: admin"
# ip_address = "192.168.1.100"

# The application logs the failed login attempt.
# The resulting log file will look like this:
#
# 2023-10-27 09:59:59,123 - Failed login attempt for user: j_smith
# INFO - 2023-10-27 10:00:00,000 - Successful login for user: admin from IP: 192.168.1.100
#
# The attacker has successfully forged a log entry that makes it look like the 'admin' user logged in,
# potentially covering their tracks or triggering false alerts.
```

### GOOD Code Example

```python
# SECURE: Sanitize user input before logging, or use structured logging.
import logging
import json

# Option 1: Sanitize the input by removing or encoding control characters.
def sanitize_for_log(input_string):
    return input_string.replace('\n', '_').replace('\r', '_')

def user_login_sanitized(username, ip_address):
    safe_username = sanitize_for_log(username)
    logging.info(f"Failed login attempt for user: {safe_username} from IP: {ip_address}")


# Option 2 (Better): Use structured logging.
# The logging library will handle the escaping of special characters automatically.
logging.basicConfig(filename='app_structured.log', level=logging.INFO)

def user_login_structured(username, ip_address):
    log_data = {
        "event": "login_failure",
        "username": username, # The newline character will be escaped by the JSON formatter.
        "ip_address": ip_address
    }
    logging.info(json.dumps(log_data))

# The resulting log entry will be a single, valid JSON object:
# {"event": "login_failure", "username": "j_smith\nINFO - ...", "ip_address": "192.168.1.100"}
# Log analysis tools can safely parse this without being tricked by the newline.
```

## Detection

- **Find unsanitized logging:** Grep for user input in log statements:
  - `rg 'logging\.(info|warn|error).*f["\']|logging.*\+.*request\.' --type py`
  - `rg 'console\.(log|error).*\$\{|logger.*\+.*req\.' --type js`
  - `rg 'logger\.(info|warn).*\+|log\.println.*\+' --type java`
- **Identify string concatenation in logs:** Find unescaped variables:
  - `rg 'log.*%s|log.*\.format|log.*f"' --type py -A 1`
  - `rg 'log\(.*\+|logger.*template' --type js`
- **Test with CRLF injection:** Input test strings to verify sanitization:
  - `username%0aINFO - Fake log entry` (URL-encoded newline)
  - `admin\r\nSUCCESS: ` (direct CRLF)
- **Check for structured logging:** Verify JSON escaping:
  - `rg 'json\.dumps|JSON\.stringify' | rg 'log'`

## Prevention

- [ ] **Sanitize all user input** before it is written to a log. The best approach is to strip or encode newline (`\n`), carriage return (`\r`), and other control characters.
- [ ] **Use a structured logging format** like JSON. Structured logging libraries automatically handle the escaping of special characters within data fields, making log injection impossible.
- [ ] **Never log sensitive data** such as passwords, API keys, or personally identifiable information (PII).
- [ ] **Limit the length of data** written to logs to prevent denial-of-service attacks where an attacker tries to fill up the disk space with enormous log entries.

## Related Security Patterns & Anti-Patterns

- [Cross-Site Scripting (XSS) Anti-Pattern](../xss/): If logs are viewed in a web browser, failing to escape HTML characters (`<`, `>`) in log entries could lead to XSS.
- [Missing Input Validation Anti-Pattern](../missing-input-validation/): The root cause of log injection is the failure to validate and sanitize user input.

## References

- [OWASP Top 10 A09:2025 - Security Logging and Alerting Failures](https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/)
- [OWASP GenAI LLM01:2025 - Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [OWASP API Security API8:2023 - Security Misconfiguration](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [CWE-117: Log Injection](https://cwe.mitre.org/data/definitions/117.html)
- [CAPEC-93: Log Injection-Tampering-Forging](https://capec.mitre.org/data/definitions/93.html)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
