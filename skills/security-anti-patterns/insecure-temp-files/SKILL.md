---
name: "insecure-temp-files-anti-pattern"
description: "Security anti-pattern for insecure temporary files (CWE-377). Use when generating or reviewing code that creates temporary files, handles file caching, or processes uploads through temp storage. Detects predictable paths, insecure permissions, and missing cleanup."
---

# Insecure Temp Files Anti-Pattern

**Severity:** Medium

## Summary
Insecure temporary file creation is a vulnerability that occurs when an application writes data to a temporary file in an unsafe manner. This anti-pattern covers three main flaws: using predictable file names, setting insecure file permissions, and failing to clean up temporary files. Attackers can exploit these flaws to read sensitive data, write malicious content, or cause denial of service. AI-generated code might suggest simplistic file handling that falls into these traps.

## The Anti-Pattern
The anti-pattern is creating and using temporary files without considering the security implications of their location, naming, permissions, and lifecycle.

### 1. Predictable File Names
Using a predictable name for a temporary file creates a race condition. An attacker can guess the file name and create a symbolic link (symlink) at that location pointing to a sensitive system file. When the application writes to its "temporary" file, it is actually overwriting the linked file.

#### BAD Code Example
```python
# VULNERABLE: Predictable temporary file name in a shared directory.
import os

def process_user_data(user_id, data):
    # The filename is easy for an attacker to guess.
    temp_path = f"/tmp/userdata_{user_id}.txt"

    # Attacker's action (done before this code runs):
    # ln -s /etc/passwd /tmp/userdata_123.txt

    # When the application writes to the temp file for user 123,
    # it is actually overwriting the system's password file.
    with open(temp_path, "w") as f:
        f.write(data)

    # ... processing logic ...
    os.remove(temp_path)
```

#### GOOD Code Example
```python
# SECURE: Use a library function that creates a securely named temporary file.
import tempfile

def process_user_data(user_id, data):
    # `tempfile.mkstemp()` creates a temporary file with a random, unpredictable name
    # and returns a low-level file handle and the path.
    # It also ensures the file is created with secure permissions (0600 on Unix).
    fd, temp_path = tempfile.mkstemp(prefix="userdata_", suffix=".txt")
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(data)
        # ... processing logic ...
    finally:
        # Always ensure the file is cleaned up.
        os.remove(temp_path)
```

### 2. Insecure Permissions and Missing Cleanup
Creating a temporary file with default permissions can make it world-readable, allowing other users on the system to access its contents. Failing to delete the temporary file after use means that sensitive data may be left behind on the disk.

#### BAD Code Example
```python
# VULNERABLE: World-readable permissions and no cleanup.
import uuid

def generate_report(data):
    # The name is random, but the permissions are not secure.
    temp_path = f"/tmp/{uuid.uuid4()}.pdf"

    # `open` with mode 'w' often uses default permissions like 0644,
    # which means other users on the system can read the file.
    with open(temp_path, "w") as f:
        f.write(data) # Sensitive report data is written.

    return temp_path # The path is returned, but the file is never deleted.
```

#### GOOD Code Example
```python
# SECURE: Guaranteed cleanup using a context manager.
import tempfile

def generate_report(data):
    # `NamedTemporaryFile` creates a file that is automatically deleted
    # when the context manager is exited.
    with tempfile.NamedTemporaryFile(mode='w', suffix='.pdf', delete=True) as temp_f:
        # The file has a secure name and permissions.
        temp_f.write(data)
        temp_f.flush()

        # You can use `temp_f.name` to get the path and pass it to other functions.
        result = send_file_to_storage(temp_f.name)

    # The temporary file is automatically and reliably deleted here,
    # even if an error occurs inside the `with` block.
    return result
```

## Detection
- Search the code for file creation in common temporary directories like `/tmp/` or `/var/tmp/`.
- Look for predictable patterns in temporary file names, such as those based on user IDs, timestamps, or simple counters.
- Check the permissions set on newly created files. Do they use secure defaults or are they overly permissive?
- Review the code to ensure that temporary files are always deleted, even in error conditions (i.e., cleanup logic is in a `finally` block or uses a context manager).

## Prevention
- [ ] **Use a trusted library** for creating temporary files, such as `tempfile` in Python or `Files.createTempFile` in Java. These libraries are designed to handle naming and permissions securely.
- [ ] **Never construct temporary file paths** using predictable names.
- [ ] **Ensure temporary files are created with restrictive permissions** (e.g., only readable and writable by the owner, 0600).
- [ ] **Always clean up temporary files.** Use `try...finally` blocks or language features like context managers (`with` in Python) to guarantee deletion.
- [ ] **Consider using in-memory buffers** (like `io.BytesIO` in Python) instead of temporary files if the data is small enough to fit in memory.

## Related Security Patterns & Anti-Patterns
- [Path Traversal Anti-Pattern](../path-traversal/): An attacker might manipulate input to control where a temporary file is written.
- [Unrestricted File Upload Anti-Pattern](../unrestricted-file-upload/): Applications often use temporary files to process uploads, making this a related risk.

## References
- [OWASP Top 10 A01:2025 - Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/)
- [OWASP GenAI LLM02:2025 - Sensitive Information Disclosure](https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/)
- [OWASP API Security API1:2023 - Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [CWE-377: Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html)
- [CAPEC-155: Screen Temporary Files for Sensitive Information](https://capec.mitre.org/data/definitions/155.html)
- [Python tempfile module](https://docs.python.org/3/library/tempfile.html)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
