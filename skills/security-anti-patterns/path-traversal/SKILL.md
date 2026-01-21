---
name: "path-traversal-anti-pattern"
description: "Security anti-pattern for path traversal vulnerabilities (CWE-22). Use when generating or reviewing code that handles file paths, reads or writes files based on user input, or serves static content. Detects joining user input to paths without proper sanitization or validation."
---

# Path Traversal Anti-Pattern

**Severity:** High

## Summary
Path traversal (also known as "directory traversal" or "dot-dot-slash") is a vulnerability that allows an attacker to read or write files outside of the intended directory. This anti-pattern occurs when an application uses user-supplied input to construct a file path without properly validating or sanitizing it. By manipulating the input with sequences like `../`, an attacker can navigate up the directory tree and access sensitive files anywhere on the server, such as `/etc/passwd`, application source code, or credentials.

## The Anti-Pattern
The anti-pattern is concatenating user input directly into a file path without first validating that the input is safe and does not contain any directory traversal characters.

### BAD Code Example
```python
# VULNERABLE: User input is directly joined with a base directory path.
from flask import request
import os

BASE_DIR = "/var/www/uploads/"

@app.route("/files/view")
def view_file():
    # The 'filename' parameter is taken directly from the request.
    filename = request.args.get("filename")

    # The user input is concatenated with the base directory.
    # No validation is performed to check for path traversal characters.
    file_path = os.path.join(BASE_DIR, filename)

    # Attacker's request: /files/view?filename=../../../../etc/passwd
    # The final `file_path` becomes: /var/www/uploads/../../../../etc/passwd
    # This resolves to: /etc/passwd

    # The application reads and returns the contents of the system's password file.
    try:
        with open(file_path, 'r') as f:
            return f.read()
    except FileNotFoundError:
        return "File not found.", 404
```

### GOOD Code Example
```python
# SECURE: The user input is validated and the final path is canonicalized.
from flask import request
import os

BASE_DIR = "/var/www/uploads/"

@app.route("/files/view/secure")
def view_file_secure():
    filename = request.args.get("filename")

    # 1. Basic validation: Check for malicious characters.
    if ".." in filename or filename.startswith("/"):
        return "Invalid filename.", 400

    # 2. Construct the full path.
    file_path = os.path.join(BASE_DIR, filename)

    # 3. Canonicalize the path: Resolve all symbolic links and `../` sequences.
    #    This is the most critical step.
    real_path = os.path.realpath(file_path)
    real_base_dir = os.path.realpath(BASE_DIR)

    # 4. Ensure the final, resolved path is still within the intended base directory.
    if not real_path.startswith(real_base_dir + os.sep):
        return "Access denied: Path is outside of the allowed directory.", 403

    # Now it is safe to access the file.
    try:
        with open(real_path, 'r') as f:
            return f.read()
    except FileNotFoundError:
        return "File not found.", 404
```

## Detection
- **Trace user input:** Follow any user-controlled input (from request parameters, body, headers, etc.) that is used in a file operation.
- **Look for path concatenation:** Search for functions that join or concatenate strings to form file paths (e.g., `os.path.join`, `+` on strings).
- **Check for missing validation:** Verify that before being used, the input is checked for path traversal sequences (`../`, `..\`). A simple search-and-replace for `../` is not sufficient due to potential bypasses like `....//`.
- **Ensure path canonicalization:** The most important check is to see if the application resolves the final path to its absolute, canonical form and then verifies that it is still within the intended base directory.

## Prevention
- [ ] **Never trust user input** when constructing file paths.
- [ ] **Validate user input** before using it. The best approach is to use a strict allowlist of known-good filenames if possible. If not, disallow path traversal sequences.
- [ ] **Canonicalize the path:** After constructing the full path, use a language-specific function (e.g., `os.path.realpath()` in Python, `File.getCanonicalPath()` in Java) to resolve it to its absolute form.
- [ ] **Verify the final path:** After canonicalization, check that the resulting path starts with the expected base directory. This is the most reliable way to prevent path traversal.
- [ ] **Use indirect references:** Instead of passing filenames, consider using IDs or indices from a predefined list of available files, so the user never directly controls a piece of the file path.

## Related Security Patterns & Anti-Patterns
- [Missing Input Validation Anti-Pattern](../missing-input-validation/): Path traversal is a specific, high-impact consequence of missing input validation.
- [Unrestricted File Upload Anti-Pattern](../unrestricted-file-upload/): An attacker might use path traversal to write a malicious file (like a web shell) to an executable directory on the server.
- [Command Injection Anti-Pattern](../command-injection/): Path traversal can be used in conjunction with command injection to execute programs from unexpected locations.

## References
- [OWASP Top 10 A05:2025 - Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)
- [OWASP GenAI LLM07:2025 - System Prompt Leakage](https://genai.owasp.org/llmrisk/llm07-system-prompt-leakage/)
- [OWASP API Security API1:2023 - Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- [CAPEC-126: Path Traversal](https://capec.mitre.org/data/definitions/126.html)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
