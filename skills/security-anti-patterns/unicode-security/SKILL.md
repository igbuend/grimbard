---
name: unicode-security-anti-pattern
description: Security anti-pattern for Unicode-related vulnerabilities (CWE-176). Use when generating or reviewing code that handles usernames, displays text, validates input, or compares strings. Detects confusable characters, normalization issues, and bidirectional text attacks.
---

# Unicode Security Anti-Pattern

**Severity:** Medium

## Risk

Unicode provides multiple ways to represent similar-looking characters, enabling attacks that bypass validation and deceive users. This leads to:

- Username spoofing (admin vs аdmin)
- Phishing through lookalike domains
- Validation bypass through normalization
- Hidden content via zero-width characters
- Source code attacks via bidirectional text

## BAD Pattern: Validation Before Normalization

```pseudocode
// VULNERABLE: Checking before normalization allows bypass

FUNCTION vulnerable_username_check(input):
    IF input == "admin":
        RETURN "Cannot register as admin"
    END IF
    RETURN "OK"
END FUNCTION

// Attack: Use Cyrillic 'а' (U+0430) which looks like Latin 'a' (U+0061)
vulnerable_username_check("аdmin")  // Returns "OK" - bypass!
// But displays as "admin" in UI, deceiving other users
```

## BAD Pattern: Ignoring Confusables

```pseudocode
// VULNERABLE: Not checking for lookalike characters

FUNCTION create_username(username):
    // No confusable check
    IF NOT exists_in_database(username):
        insert_user(username)
        RETURN "User created"
    END IF
    RETURN "Username taken"
END FUNCTION

// Attacker registers "pаypal" (Cyrillic 'а')
// Legitimate user has "paypal" (Latin 'a')
// Users see both as "paypal" - phishing possible
```

## BAD Pattern: Zero-Width Character Issues

```pseudocode
// VULNERABLE: Zero-width characters hidden in input

FUNCTION check_admin_command(input):
    IF input == "delete_all":
        RETURN "Admin command blocked"
    END IF
    execute_command(input)
END FUNCTION

// Attack: "dele\u200Bte_all" contains zero-width space
// String comparison fails, but command might execute
// Or: displays as "delete_all" but stored differently
```

## GOOD Pattern: Normalize Then Validate

```pseudocode
// SECURE: Normalize and check for confusables

FUNCTION secure_username_check(input):
    // Step 1: Unicode normalize to NFC
    normalized = unicode_normalize(input, "NFC")

    // Step 2: Convert confusables to ASCII equivalent
    ascii_skeleton = confusables_skeleton(normalized)

    // Step 3: Check reserved names against skeleton
    reserved_names = ["admin", "root", "system", "administrator", "support"]
    IF ascii_skeleton.to_lower() IN reserved_names:
        RETURN {valid: FALSE, error: "Reserved username"}
    END IF

    // Step 4: Only allow safe character set
    IF NOT is_ascii_alphanumeric(input):
        RETURN {valid: FALSE, error: "Username must be ASCII letters and numbers"}
    END IF

    RETURN {valid: TRUE, value: normalized}
END FUNCTION
```

## GOOD Pattern: Confusable Detection

```pseudocode
// SECURE: Check for confusable characters

FUNCTION check_username_confusables(new_username, existing_usernames):
    // Get skeleton of new username
    new_skeleton = confusables_skeleton(new_username)

    FOR existing IN existing_usernames:
        existing_skeleton = confusables_skeleton(existing)

        IF new_skeleton == existing_skeleton AND new_username != existing:
            RETURN {
                valid: FALSE,
                error: "Username too similar to existing: " + existing
            }
        END IF
    END FOR

    RETURN {valid: TRUE}
END FUNCTION

// Unicode confusables skeleton converts lookalikes to canonical form
// "pаypal" (Cyrillic а) -> "paypal"
// "paypal" (Latin a) -> "paypal"
// Both produce same skeleton -> detected as confusable
```

## GOOD Pattern: Strip Dangerous Characters

```pseudocode
// SECURE: Remove zero-width and control characters

FUNCTION sanitize_unicode(input):
    result = input

    // Remove zero-width characters
    zero_width = [
        "\u200B",  // Zero-width space
        "\u200C",  // Zero-width non-joiner
        "\u200D",  // Zero-width joiner
        "\uFEFF",  // Zero-width no-break space (BOM)
    ]
    FOR char IN zero_width:
        result = result.replace(char, "")
    END FOR

    // Remove bidirectional override characters
    bidi_chars = [
        "\u202A",  // Left-to-right embedding
        "\u202B",  // Right-to-left embedding
        "\u202C",  // Pop directional formatting
        "\u202D",  // Left-to-right override
        "\u202E",  // Right-to-left override
        "\u2066",  // Left-to-right isolate
        "\u2067",  // Right-to-left isolate
        "\u2068",  // First strong isolate
        "\u2069",  // Pop directional isolate
    ]
    FOR char IN bidi_chars:
        result = result.replace(char, "")
    END FOR

    RETURN result
END FUNCTION
```

## Common Unicode Attack Vectors

| Attack | Example | Risk |
|--------|---------|------|
| Confusables | `аdmin` (Cyrillic) | Username spoofing |
| Homoglyphs | `pаypal.com` | Phishing domains |
| Zero-width | `pass\u200Bword` | Validation bypass |
| BiDi override | `\u202Efdp.exe` | Shows as "exe.pdf" |
| Normalization | `ﬁle` (ligature) | `file` after NFC |

## Detection

- Test with Unicode confusables for admin/root/system
- Check inputs with zero-width characters
- Test with combining characters and ligatures
- Verify bidirectional text handling
- Use Unicode security tools and libraries

## Prevention Checklist

- [ ] Normalize Unicode (NFC) before validation
- [ ] Check for confusable characters (skeleton comparison)
- [ ] Strip zero-width and control characters
- [ ] Restrict to ASCII for security-critical identifiers
- [ ] Block or escape bidirectional override characters
- [ ] Use Unicode security libraries (ICU, Python unicodedata)
- [ ] Consider displaying Punycode for international domains

## Related Patterns

- [encoding-bypass](../encoding-bypass/) - Related encoding attacks
- [missing-input-validation](../missing-input-validation/) - Validation fundamentals
- [xss](../xss/) - Unicode in XSS payloads

## References

- [OWASP Top 10 A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [CWE-176: Improper Handling of Unicode](https://cwe.mitre.org/data/definitions/176.html)
- [CAPEC-71: Using Unicode Encoding to Bypass Validation](https://capec.mitre.org/data/definitions/71.html)
- [Unicode Security Considerations](https://unicode.org/reports/tr36/)
- [Unicode Confusables](https://util.unicode.org/UnicodeJsps/confusables.jsp)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
