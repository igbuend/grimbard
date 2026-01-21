---
name: "command-injection-anti-pattern"
description: "Security anti-pattern for OS Command Injection vulnerabilities (CWE-78). Use when generating or reviewing code that executes shell commands, runs system processes, or handles user input in command-line operations. Detects shell string concatenation and recommends argument arrays."
---

# Command Injection Anti-Pattern

**Severity:** Critical

## Summary

Command injection is a critical vulnerability that allows attackers to execute arbitrary operating system commands by manipulating user input. This anti-pattern arises when an application constructs and executes shell commands by concatenating user-provided data into a command string. This is a common and dangerous practice often found in AI-generated code. A successful attack can lead to complete system compromise, data exfiltration, malware installation, and lateral movement within a network.

## The Anti-Pattern

The command injection anti-pattern occurs when user input is insecurely embedded within a command string that is executed by a shell interpreter. The shell cannot distinguish between the intended command and the attacker's injected commands.

### BAD Code Example

```python
# VULNERABLE: Shell command with user input
import os

def ping_host(hostname):
    # User input is directly concatenated into the command string.
    # An attacker can inject malicious commands separated by a semicolon or other shell metacharacters.
    command = "ping -c 4 " + hostname
    os.system(command)

# Example of a successful attack:
# hostname = "google.com; rm -rf /"
# Resulting command: "ping -c 4 google.com; rm -rf /"
# This executes the ping and then attempts to delete the entire filesystem.
```

### GOOD Code Example

```python
# SECURE: Use argument arrays, avoid shell
import subprocess

def ping_host(hostname):
    # Input should be validated against an allowlist of characters or a specific format.
    # For simplicity, this example proceeds directly to safe execution.

    # The command and its arguments are passed as a list.
    # The underlying OS API executes the command directly without invoking a shell,
    # so shell metacharacters in `hostname` are treated as a literal string.
    try:
        subprocess.run(["ping", "-c", "4", hostname], check=True, shell=False)
    except subprocess.CalledProcessError as e:
        print(f"Error executing ping: {e}")

```

## Detection

- Look for the use of functions that execute shell commands, such as `os.system()`, `subprocess.popen()`, or `subprocess.run()` with `shell=True`.
- Search for string concatenation (`+`), f-strings, or template literals used to build command strings that include user input.
- Review any code where user-controlled variables are passed into functions that execute system commands.

## Prevention

- [ ] **Use argument arrays** instead of shell strings (e.g., `subprocess.run(["command", "arg1", "arg2"], shell=False)`).
- [ ] **Never pass `shell=True`** with user-controlled input to execution functions.
- [ ] **Validate all input** against a strict allowlist of known-good values or formats.
- [ ] **Use language-specific libraries or APIs** instead of external shell commands whenever possible.
- [ ] **Apply the Principle of Least Privilege** to the process executing the command, restricting its permissions to the absolute minimum required.

## Related Security Patterns & Anti-Patterns

- [SQL Injection Anti-Pattern](../sql-injection/): A similar injection pattern targeting databases.
- [Path Traversal Anti-Pattern](../path-traversal/): Often combined with command injection to access or create files in unintended locations.
- [Missing Input Validation Anti-Pattern](../missing-input-validation/): A fundamental weakness that enables command injection.

## References

- [OWASP Top 10 A05:2025 - Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)
- [OWASP GenAI LLM01:2025 - Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [OWASP API Security API8:2023 - Security Misconfiguration](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/)
- [OWASP OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [CAPEC-88: OS Command Injection](https://capec.mitre.org/data/definitions/88.html)
- [PortSwigger: Os Command Injection](https://portswigger.net/web-security/os-command-injection)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
