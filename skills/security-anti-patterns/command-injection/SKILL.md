---
name: command-injection-anti-pattern
description: Security anti-pattern for OS command injection vulnerabilities (CWE-78). Use when generating or reviewing code that executes shell commands, runs system processes, or handles user input in command-line operations. Detects shell string concatenation and recommends argument arrays.
---

# Command Injection Anti-Pattern

**CWE:** CWE-78 (Improper Neutralization of Special Elements used in an OS Command)
**CAPEC:** [CAPEC-88: OS Command Injection](https://capec.mitre.org/data/definitions/88.html)
**Severity:** Critical
**OWASP:** A03:2021 - Injection

## Risk

Command injection allows attackers to execute arbitrary OS commands by manipulating user input passed to shell commands. This can lead to:

- Complete system compromise
- Data exfiltration
- Malware installation
- Lateral movement in networks

AI models frequently generate vulnerable shell command concatenation from tutorial examples in training data.

## BAD Pattern

```pseudocode
// VULNERABLE: Shell command with user input

FUNCTION ping_host(hostname):
    // User controls shell command
    command = "ping -c 4 " + hostname
    RETURN shell.execute(command)
END FUNCTION

FUNCTION convert_file(input_path, output_format):
    // Multiple injection points
    command = "convert " + input_path + " output." + output_format
    RETURN shell.execute(command)
END FUNCTION

// Attack: hostname = "google.com; rm -rf /"
// Result: ping -c 4 google.com; rm -rf /
// This executes the ping AND deletes the filesystem

// Attack: hostname = "$(cat /etc/passwd)"
// Result: Command substitution exposes sensitive files
```

## GOOD Pattern

```pseudocode
// SECURE: Use argument arrays, avoid shell

FUNCTION ping_host(hostname):
    // Validate input format first
    IF NOT is_valid_hostname(hostname):
        THROW Error("Invalid hostname format")
    END IF

    // Arguments passed as array, no shell interpolation
    RETURN process.execute(["ping", "-c", "4", hostname], shell=FALSE)
END FUNCTION

FUNCTION convert_file(input_path, output_format):
    // Validate allowed formats (allowlist)
    allowed_formats = ["png", "jpg", "gif", "webp"]
    IF output_format NOT IN allowed_formats:
        THROW Error("Invalid output format")
    END IF

    // Validate path is within allowed directory
    IF NOT path.is_within(input_path, UPLOAD_DIRECTORY):
        THROW Error("Invalid file path")
    END IF

    output_path = path.join(OUTPUT_DIR, "output." + output_format)
    RETURN process.execute(["convert", input_path, output_path], shell=FALSE)
END FUNCTION

// Helper: Validate hostname format
FUNCTION is_valid_hostname(hostname):
    // Only allow alphanumeric, dots, and hyphens
    pattern = "^[a-zA-Z0-9][a-zA-Z0-9.-]{0,253}[a-zA-Z0-9]$"
    RETURN regex.match(pattern, hostname)
END FUNCTION
```

## Detection

- Look for `shell=True`, `system()`, `exec()`, `popen()`, backticks, or `$()` with user input
- Search for string concatenation building command strings
- Check for user input passed to subprocess/process execution functions
- Review any code that dynamically constructs shell commands

## Prevention Checklist

- [ ] Use argument arrays instead of shell strings (e.g., `subprocess.run([...], shell=False)`)
- [ ] Never pass `shell=True` with user-controlled input
- [ ] Validate all input against strict allowlists
- [ ] Use libraries/APIs instead of shell commands when possible
- [ ] Apply principle of least privilege to process execution

## Related Patterns

- [sql-injection](../sql-injection/) - Similar injection pattern for databases
- [path-traversal](../path-traversal/) - Often combined with command injection
- [missing-input-validation](../missing-input-validation/) - Root cause enabler

## References

- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [OWASP OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
