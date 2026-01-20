---
name: encoding-bypass-anti-pattern
description: Security anti-pattern for encoding bypass vulnerabilities (CWE-838). Use when generating or reviewing code that handles URL encoding, Unicode normalization, or character set conversions before security validation. Detects validation before normalization and double-encoding issues.
---

# Encoding Bypass Anti-Pattern

**Severity:** High

## Risk

Encoding bypass attacks exploit the order of operations between encoding/decoding and security validation. When validation happens before normalization, attackers can sneak malicious payloads through using alternate encodings. This leads to:

- WAF and filter bypass
- Injection attacks through encoded payloads
- XSS through character encoding tricks
- Authentication bypass via Unicode confusables

## BAD Pattern: Double-Encoding Bypass

```pseudocode
// VULNERABLE: Double-encoding bypasses single decode + validation

FUNCTION search_with_filter(term):
    // Application URL-decodes once
    decoded = url_decode(term)  // %2527 -> %27

    // WAF or validation sees %27, not single quote
    IF contains_dangerous_chars(decoded):
        THROW ValidationError("Invalid characters")
    END IF

    // Later, another decode happens (framework, database driver, etc.)
    // %27 -> '

    query = "SELECT * FROM items WHERE name = '" + decoded + "'"
    // Injection succeeds with original input: %2527 (double-encoded ')
END FUNCTION
```

## BAD Pattern: Validation Before Unicode Normalization

```pseudocode
// VULNERABLE: Unicode normalization happens AFTER validation

FUNCTION filter_username(username):
    // Check for dangerous characters
    IF "'" IN username OR '"' IN username:
        THROW ValidationError("Invalid characters")
    END IF

    // VULNERABLE: Unicode normalization happens AFTER validation
    normalized = unicode_normalize(username)
    // 'ʼ' (U+02BC MODIFIER LETTER APOSTROPHE) might normalize to "'" (U+0027)
    // 'ＡＢＣ' (fullwidth) normalizes to 'ABC'

    query = "SELECT * FROM users WHERE username = '" + normalized + "'"
    // Attack: username = "adminʼ--" bypasses check, normalizes to "admin'--"
END FUNCTION
```

## BAD Pattern: Character Set Confusion

```pseudocode
// VULNERABLE: Mixed character set handling

FUNCTION process_input(request):
    // Input declared as UTF-8 but actually contains Latin-1
    input = request.body  // Browser sends mixed encoding

    // Validation assumes UTF-8
    IF NOT is_valid_utf8(input):
        // Might skip validation or misinterpret bytes
        input = force_utf8(input)  // Lossy conversion
    END IF

    // Dangerous characters may slip through encoding confusion
    RETURN process(input)
END FUNCTION
```

## GOOD Pattern: Parameterization Makes Encoding Irrelevant

```pseudocode
// SECURE: Parameterization - encoding doesn't matter

FUNCTION search_safe(term):
    // Encoding doesn't matter - it's just data
    query = "SELECT * FROM items WHERE name = ?"
    RETURN database.execute(query, [term])
END FUNCTION
```

## GOOD Pattern: Normalize Then Validate

```pseudocode
// SECURE: Validate AFTER all normalization

FUNCTION filter_username_safe(username):
    // Step 1: Decode all encodings first
    decoded = url_decode(username)

    // Step 2: Normalize Unicode
    normalized = unicode_normalize(decoded, form="NFC")

    // Step 3: Convert to consistent character set
    canonical = to_ascii_safe(normalized)  // or validate UTF-8

    // Step 4: THEN validate
    IF NOT is_valid_username_chars(canonical):
        THROW ValidationError("Invalid characters")
    END IF

    // Step 5: Use with parameterization anyway
    query = "SELECT * FROM users WHERE username = ?"
    RETURN database.execute(query, [canonical])
END FUNCTION
```

## GOOD Pattern: Strict Encoding Validation

```pseudocode
// SECURE: Reject ambiguous encodings entirely

FUNCTION process_input_safe(request):
    // Enforce strict UTF-8
    IF NOT is_strict_utf8(request.body):
        THROW ValidationError("Invalid encoding - must be UTF-8")
    END IF

    // Reject overlong encodings (UTF-8 attack vector)
    IF contains_overlong_encoding(request.body):
        THROW ValidationError("Invalid UTF-8 encoding")
    END IF

    // Now safe to process
    RETURN process(request.body)
END FUNCTION
```

## Common Encoding Bypass Techniques

| Technique | Example | Decoded |
|-----------|---------|---------|
| URL encoding | `%27` | `'` |
| Double URL encoding | `%2527` | `%27` -> `'` |
| Unicode | `\u0027` | `'` |
| HTML entities | `&#39;` or `&#x27;` | `'` |
| Overlong UTF-8 | `%c0%a7` | `/` (invalid encoding) |
| Fullwidth | `'` (U+FF07) | May normalize to `'` |
| Homoglyphs | `ʼ` (U+02BC) | Looks like `'` |

## Detection

- Test with various encoded payloads (`%27`, `%2527`, Unicode variants)
- Check if validation happens before or after decoding/normalization
- Look for multiple decode operations in the request pipeline
- Review character set handling and conversion code
- Test with homoglyphs and Unicode confusables

## Prevention Checklist

- [ ] Always normalize/decode BEFORE validation
- [ ] Use parameterized queries (makes encoding irrelevant for SQL)
- [ ] Enforce strict character encoding (reject invalid UTF-8)
- [ ] Canonicalize paths and URLs before validation
- [ ] Be aware of framework auto-decoding behavior
- [ ] Test with double-encoded and Unicode payloads
- [ ] Consider using allowlists for acceptable characters

## Related Patterns

- [sql-injection](../sql-injection/) - Primary target of encoding bypass
- [xss](../xss/) - XSS through encoding tricks
- [path-traversal](../path-traversal/) - Path encoding bypass
- [unicode-security](../unicode-security/) - Related Unicode issues

## References

- [OWASP Top 10 A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [OWASP Testing for HTTP Incoming Requests](https://owasp.org/www-project-web-security-testing-guide/)
- [CWE-838: Inappropriate Encoding for Output Context](https://cwe.mitre.org/data/definitions/838.html)
- [CAPEC-267: Leverage Alternate Encoding](https://capec.mitre.org/data/definitions/267.html)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
