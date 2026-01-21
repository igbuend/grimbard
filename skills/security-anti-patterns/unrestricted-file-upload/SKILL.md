---
name: unrestricted-file-upload-anti-pattern
description: Security anti-pattern for unrestricted file upload vulnerabilities (CWE-434). Use when generating or reviewing code that handles file uploads, processes user-submitted files, or stores uploaded content. Detects missing extension, MIME type, and size validation.
---

# Unrestricted File Upload Anti-Pattern

**Severity:** Critical

## Risk

Unrestricted file uploads allow attackers to upload malicious files that can lead to:

- Remote code execution (uploading web shells)
- Server compromise
- Cross-site scripting via HTML/SVG files
- Storage exhaustion (DoS)
- Malware distribution

## BAD Pattern: No File Validation

```pseudocode
// VULNERABLE: Accepts any file type and size

FUNCTION upload_file(request):
    file = request.files.get("upload")

    // No validation at all!
    filename = file.filename
    file.save("/uploads/" + filename)

    RETURN {success: TRUE, filename: filename}
END FUNCTION

// Attack: Upload "shell.php" with PHP code
// Result: Web shell accessible at /uploads/shell.php
```

## GOOD Pattern: Comprehensive File Validation

```pseudocode
// SECURE: Validate extension, MIME type, size, and content

CONSTANT MAX_FILE_SIZE = 10 * 1024 * 1024  // 10MB
CONSTANT ALLOWED_EXTENSIONS = [".jpg", ".jpeg", ".png", ".gif", ".pdf"]
CONSTANT ALLOWED_MIME_TYPES = [
    "image/jpeg", "image/png", "image/gif", "application/pdf"
]

FUNCTION upload_file(request):
    file = request.files.get("upload")

    IF file IS NULL:
        THROW ValidationError("No file provided")
    END IF

    // 1. Check file size
    IF file.size > MAX_FILE_SIZE:
        THROW ValidationError("File too large (max 10MB)")
    END IF

    // 2. Check extension (allowlist)
    original_name = file.filename
    extension = path.get_extension(original_name).lower()
    IF extension NOT IN ALLOWED_EXTENSIONS:
        THROW ValidationError("File type not allowed")
    END IF

    // 3. Check MIME type (don't trust Content-Type header alone)
    declared_mime = file.content_type
    IF declared_mime NOT IN ALLOWED_MIME_TYPES:
        THROW ValidationError("Invalid file type")
    END IF

    // 4. Verify actual content (magic bytes)
    actual_mime = detect_mime_type(file.content)
    IF actual_mime NOT IN ALLOWED_MIME_TYPES:
        log.warning("MIME type mismatch", {
            declared: declared_mime,
            actual: actual_mime
        })
        THROW ValidationError("File content doesn't match type")
    END IF

    // 5. Generate safe filename (never use original)
    safe_filename = uuid() + extension

    // 6. Save outside web root or with no-execute permissions
    file.save(UPLOAD_DIR + "/" + safe_filename)

    RETURN {success: TRUE, filename: safe_filename}
END FUNCTION
```

## BAD Pattern: Extension-Only Check

```pseudocode
// VULNERABLE: Only checks extension (easily bypassed)

FUNCTION upload_image_weak(request):
    file = request.files.get("image")
    filename = file.filename

    // Bypass: "shell.php.jpg" or "shell.jpg.php"
    IF NOT filename.ends_with(".jpg") AND NOT filename.ends_with(".png"):
        THROW ValidationError("Only images allowed")
    END IF

    file.save("/uploads/" + filename)
END FUNCTION
```

## GOOD Pattern: Multi-Layer Validation

```pseudocode
// SECURE: Multiple validation layers

FUNCTION validate_image_upload(file):
    // Layer 1: Extension allowlist
    extension = path.get_extension(file.filename).lower()
    IF extension NOT IN [".jpg", ".jpeg", ".png", ".gif"]:
        RETURN {valid: FALSE, reason: "Invalid extension"}
    END IF

    // Layer 2: Magic bytes verification
    magic_bytes = file.read(8)
    IF NOT is_valid_image_header(magic_bytes):
        RETURN {valid: FALSE, reason: "Invalid file header"}
    END IF

    // Layer 3: Try to parse as image
    TRY:
        image = image_library.open(file)
        image.verify()  // Validates image structure
    CATCH ImageError:
        RETURN {valid: FALSE, reason: "Corrupt or invalid image"}
    END TRY

    // Layer 4: Check for embedded content
    IF contains_script_tags(file.content):
        RETURN {valid: FALSE, reason: "Suspicious content detected"}
    END IF

    RETURN {valid: TRUE}
END FUNCTION
```

## File Type Magic Bytes

| Type | Magic Bytes (hex) |
|------|-------------------|
| JPEG | `FF D8 FF` |
| PNG | `89 50 4E 47 0D 0A 1A 0A` |
| GIF | `47 49 46 38` |
| PDF | `25 50 44 46` |
| ZIP | `50 4B 03 04` |

## Detection

- Look for file upload handlers without extension validation
- Search for user-provided filenames used directly
- Check for missing MIME type verification
- Review upload directories for execute permissions

## Prevention Checklist

- [ ] Validate file extension against strict allowlist
- [ ] Verify MIME type matches extension
- [ ] Check magic bytes to confirm actual file type
- [ ] Enforce maximum file size limits
- [ ] Generate random filenames (never use user input)
- [ ] Store uploads outside web root
- [ ] Set no-execute permissions on upload directories
- [ ] Scan uploads for malware

## Related Patterns

- [path-traversal](../path-traversal/) - Filename manipulation
- [command-injection](../command-injection/) - Processing uploaded files
- [xss](../xss/) - HTML/SVG uploads can contain scripts

## References

- [OWASP Top 10 A06:2025 - Insecure Design](https://owasp.org/Top10/2025/A06_2025-Insecure_Design/)
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [CWE-434: Unrestricted File Upload](https://cwe.mitre.org/data/definitions/434.html)
- [CAPEC-1: Accessing Functionality Not Properly Constrained by ACLs](https://capec.mitre.org/data/definitions/1.html)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
