---
name: insecure-temp-files-anti-pattern
description: Security anti-pattern for insecure temporary files (CWE-377). Use when generating or reviewing code that creates temporary files, handles file caching, or processes uploads through temp storage. Detects predictable paths, insecure permissions, and missing cleanup.
---

# Insecure Temp Files Anti-Pattern

**Severity:** Medium

## Risk

Insecure temporary file handling allows attackers to:

- Read sensitive data from predictable temp paths
- Write malicious content to temp files before use (race condition)
- Symlink attacks redirecting file operations
- Information disclosure via leftover temp files

## BAD Pattern: Predictable Temp File Names

```pseudocode
// VULNERABLE: Predictable filename

FUNCTION process_upload(data):
    // Predictable: attacker knows where file will be
    temp_path = "/tmp/upload_" + user_id + ".dat"

    write_file(temp_path, data)  // Attacker could symlink here
    process_file(temp_path)
    delete_file(temp_path)
END FUNCTION

FUNCTION export_report(user_id):
    // Predictable: attacker can guess and access
    temp_path = "/tmp/report_" + user_id + ".pdf"
    generate_report(temp_path)
    send_file(temp_path)
    // Missing cleanup!
END FUNCTION
```

## GOOD Pattern: Secure Temp File Creation

```pseudocode
// SECURE: Use mkstemp or equivalent

FUNCTION process_upload(data):
    // Create file with random name and secure permissions
    // mkstemp creates file with 0600 permissions atomically
    temp_fd, temp_path = mkstemp(prefix="upload_", suffix=".dat")

    TRY:
        write_to_fd(temp_fd, data)
        close_fd(temp_fd)
        process_file(temp_path)
    FINALLY:
        // Always cleanup
        delete_file(temp_path)
    END TRY
END FUNCTION

FUNCTION export_report(user_id):
    // Use system temp directory with random name
    temp_dir = mkdtemp(prefix="report_")

    TRY:
        temp_path = path.join(temp_dir, "report.pdf")
        generate_report(temp_path)
        send_file(temp_path)
    FINALLY:
        // Cleanup entire temp directory
        remove_directory(temp_dir, recursive=TRUE)
    END TRY
END FUNCTION
```

## BAD Pattern: Insecure Permissions

```pseudocode
// VULNERABLE: World-readable temp file

FUNCTION cache_sensitive_data(data):
    temp_path = "/tmp/cache_" + random_string() + ".dat"

    // File created with default permissions (often 0644)
    write_file(temp_path, data)

    // Other users on system can read this!
END FUNCTION
```

## GOOD Pattern: Restrictive Permissions

```pseudocode
// SECURE: Explicit restrictive permissions

FUNCTION cache_sensitive_data(data):
    // Create with restrictive permissions from the start
    temp_fd, temp_path = mkstemp(prefix="cache_")

    // mkstemp creates with 0600 by default
    // Or explicitly set permissions
    set_permissions(temp_path, 0o600)  // Owner read/write only

    write_to_fd(temp_fd, data)
    close_fd(temp_fd)

    RETURN temp_path
END FUNCTION

// For directories
FUNCTION create_secure_temp_dir():
    // mkdtemp creates with 0700 permissions
    temp_dir = mkdtemp(prefix="secure_")
    RETURN temp_dir
END FUNCTION
```

## BAD Pattern: Missing Cleanup

```pseudocode
// VULNERABLE: Temp files not cleaned up

FUNCTION process_batch(items):
    temp_files = []

    FOR item IN items:
        temp_path = create_temp_file(item.data)
        temp_files.append(temp_path)
        process_item(temp_path)
        // Forgot to delete!
    END FOR

    // Sensitive data remains in /tmp
END FUNCTION
```

## GOOD Pattern: Guaranteed Cleanup

```pseudocode
// SECURE: Use context managers/try-finally

FUNCTION process_batch(items):
    temp_files = []

    TRY:
        FOR item IN items:
            temp_fd, temp_path = mkstemp()
            temp_files.append(temp_path)
            write_to_fd(temp_fd, item.data)
            close_fd(temp_fd)
            process_item(temp_path)
        END FOR
    FINALLY:
        // Always cleanup, even on error
        FOR path IN temp_files:
            TRY:
                delete_file(path)
            CATCH:
                log.warning("Failed to delete temp file", {path: path})
            END TRY
        END FOR
    END TRY
END FUNCTION

// Or use automatic temp file that deletes on close
FUNCTION process_single(data):
    // NamedTemporaryFile auto-deletes when closed
    WITH temp_file = NamedTemporaryFile(delete=TRUE) AS f:
        f.write(data)
        f.flush()
        process_file(f.name)
    END WITH
    // File automatically deleted here
END FUNCTION
```

## Secure Temp File Checklist

| Requirement | Implementation |
|-------------|----------------|
| Random name | Use `mkstemp()`, not custom random |
| Secure permissions | 0600 for files, 0700 for dirs |
| Atomic creation | `mkstemp()` creates atomically |
| Guaranteed cleanup | try-finally or context managers |
| Secure directory | Use system temp or app-specific |

## Detection

- Search for `/tmp/` with predictable patterns
- Look for `open(temp_path, 'w')` without mkstemp
- Check for missing cleanup in file processing
- Review for world-readable temp file creation

## Prevention Checklist

- [ ] Use `mkstemp()` or `mkdtemp()` for temp files/dirs
- [ ] Never construct temp paths with predictable names
- [ ] Set permissions to 0600 (files) or 0700 (directories)
- [ ] Always clean up temp files in finally blocks
- [ ] Use context managers for automatic cleanup
- [ ] Consider using in-memory buffers instead of temp files
- [ ] Set TMPDIR to application-specific secure directory

## Related Patterns

- [path-traversal](../path-traversal/) - Temp file path manipulation
- [unrestricted-file-upload](../unrestricted-file-upload/) - Upload to temp

## References

- [OWASP Top 10 A01:2021 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-377: Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html)
- [CAPEC-155: Screen Temporary Files for Sensitive Information](https://capec.mitre.org/data/definitions/155.html)
- [Python tempfile module](https://docs.python.org/3/library/tempfile.html)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
