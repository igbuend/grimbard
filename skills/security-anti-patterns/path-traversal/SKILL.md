---
name: path-traversal-anti-pattern
description: Security anti-pattern for path traversal vulnerabilities (CWE-22). Use when generating or reviewing code that handles file paths, reads/writes files based on user input, or serves static files. Detects missing path canonicalization and directory validation.
---

# Path Traversal Anti-Pattern

**CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
**CAPEC:** [CAPEC-126: Path Traversal](https://capec.mitre.org/data/definitions/126.html)
**Severity:** High
**OWASP:** A01:2021 - Broken Access Control

## Risk

Path traversal allows attackers to access files outside intended directories using sequences like `../`. This leads to:

- Reading sensitive configuration files
- Accessing source code
- Reading `/etc/passwd` or other system files
- Potential code execution via log poisoning

## BAD Pattern: Direct Path Usage

```pseudocode
// VULNERABLE: User input used directly in path

FUNCTION get_file(request):
    filename = request.params.filename
    // Attacker: filename = "../../../etc/passwd"
    path = "/uploads/" + filename
    RETURN read_file(path)
END FUNCTION

FUNCTION serve_image(request):
    image = request.params.image
    // Bypass: image = "....//....//etc/passwd"
    RETURN send_file("/images/" + image)
END FUNCTION
```

## GOOD Pattern: Path Canonicalization

```pseudocode
// SECURE: Canonicalize and validate path

FUNCTION get_file(request):
    filename = request.params.filename

    // Reject obvious traversal attempts
    IF filename.contains("..") OR filename.contains("\x00"):
        THROW AccessDenied("Invalid filename")
    END IF

    // Canonicalize both paths
    base_path = path.resolve("/uploads")
    requested_path = path.resolve(path.join("/uploads", filename))

    // Verify resolved path is within allowed directory
    IF NOT requested_path.starts_with(base_path):
        log.warning("Path traversal attempt", {
            requested: filename,
            resolved: requested_path
        })
        THROW AccessDenied("Invalid path")
    END IF

    // Verify file exists
    IF NOT file_exists(requested_path):
        THROW NotFound("File not found")
    END IF

    RETURN read_file(requested_path)
END FUNCTION
```

## BAD Pattern: Validation Before Canonicalization

```pseudocode
// VULNERABLE: Validates before resolving path

FUNCTION check_path_unsafe(requested_path):
    // This check happens BEFORE path resolution
    IF requested_path.starts_with("/uploads/"):
        // Bypass: "../../../etc/passwd" doesn't match
        // but resolves outside /uploads/
        RETURN read_file(requested_path)
    END IF
    THROW AccessDenied("Invalid path")
END FUNCTION
```

## GOOD Pattern: Canonicalize Then Validate

```pseudocode
// SECURE: Canonicalize THEN validate

FUNCTION check_path_safe(requested_path):
    // Canonicalize first
    base_path = path.resolve("/uploads")
    canonical_path = path.resolve(path.join(base_path, requested_path))

    // Validate AFTER canonicalization
    IF NOT canonical_path.starts_with(base_path + "/"):
        THROW AccessDenied("Invalid path")
    END IF

    RETURN read_file(canonical_path)
END FUNCTION
```

## Common Bypass Techniques

| Technique | Example |
|-----------|---------|
| Basic traversal | `../../../etc/passwd` |
| Double encoding | `%252e%252e%252f` |
| Null byte | `../../../etc/passwd%00.jpg` |
| Unicode | `..%c0%af..%c0%af` |
| Double dots | `....//....//` |
| Backslash (Windows) | `..\..\..\windows\win.ini` |

## Detection

- Look for user input concatenated with file paths
- Search for `path.join()` or string concatenation with user data
- Check for missing `path.resolve()` or `realpath()` calls
- Review file serving code for path validation

## Prevention Checklist

- [ ] Canonicalize paths using `path.resolve()` or `realpath()`
- [ ] Validate canonical path is within allowed directory
- [ ] Reject input containing `..`, null bytes, or path separators
- [ ] Use allowlist of permitted filenames when possible
- [ ] Generate safe filenames (UUID) for user uploads
- [ ] Set filesystem permissions as additional defense

## Related Patterns

- [unrestricted-file-upload](../unrestricted-file-upload/) - Often combined with traversal
- [command-injection](../command-injection/) - File paths in commands
- [missing-input-validation](../missing-input-validation/) - Root cause

## References

- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
