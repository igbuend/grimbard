---
name: missing-input-validation-anti-pattern
description: Security anti-pattern for missing input validation (CWE-20). Use when generating or reviewing code that processes user input, form data, API parameters, or external data. Detects client-only validation, missing type checks, and absent length limits. Foundation vulnerability enabling most attack classes.
---

# Missing Input Validation Anti-Pattern

**CWE:** CWE-20 (Improper Input Validation)
**CAPEC:** [CAPEC-153: Input Data Manipulation](https://capec.mitre.org/data/definitions/153.html)
**Severity:** High
**OWASP:** A03:2021 - Injection (enables), A04:2021 - Insecure Design

## Risk

Input validation failures are foundational vulnerabilities enabling most other attack classes including injection, XSS, and DoS. AI-generated code frequently relies solely on client-side validation (trivially bypassed) or omits validation entirely. This leads to:

- Injection attacks (SQL, command, XSS)
- Type confusion vulnerabilities
- Denial of service via large inputs
- Business logic bypass

## BAD Pattern: Client-Side Only Validation

```pseudocode
// VULNERABLE: Only validates in browser

// Frontend JavaScript
FUNCTION validate_form_client_only():
    email = document.getElementById("email").value
    IF NOT email.includes("@"):
        show_error("Invalid email")
        RETURN FALSE
    END IF
    form.submit()
END FUNCTION

// Backend - NO validation!
FUNCTION create_user(request):
    // Trusts client-side validation completely
    email = request.body.email
    database.insert("users", {email: email})
END FUNCTION

// Attack: curl -X POST /api/users -d '{"email":"not-an-email"}'
```

## GOOD Pattern: Server-Side Validation

```pseudocode
// SECURE: Validates all input server-side

FUNCTION create_user(request):
    validation_errors = []

    // Email validation
    email = request.body.email
    IF typeof(email) != "string":
        validation_errors.append("Email must be a string")
    ELSE IF NOT regex.match("^[^@]+@[^@]+\.[^@]+$", email):
        validation_errors.append("Invalid email format")
    ELSE IF email.length > 254:
        validation_errors.append("Email too long")
    END IF

    IF validation_errors.length > 0:
        RETURN {success: FALSE, errors: validation_errors}
    END IF

    database.insert("users", {email: email})
    RETURN {success: TRUE}
END FUNCTION
```

## BAD Pattern: Missing Type Checking

```pseudocode
// VULNERABLE: No type validation

FUNCTION process_payment(request):
    amount = request.body.amount  // Could be string, array, object!
    total = amount * quantity     // Type coercion issues
    charge_card(user, total)
END FUNCTION

// Attack: {"amount": {"$gt": 0}} - NoSQL injection possible
```

## GOOD Pattern: Strict Type Validation

```pseudocode
// SECURE: Explicit type checking

FUNCTION process_payment(request):
    amount = request.body.amount

    IF typeof(amount) != "number":
        THROW ValidationError("Amount must be a number")
    END IF
    IF NOT is_finite(amount) OR is_nan(amount):
        THROW ValidationError("Amount must be a valid number")
    END IF
    IF amount <= 0:
        THROW ValidationError("Amount must be positive")
    END IF

    total = amount * quantity
    charge_card(user, total)
END FUNCTION
```

## BAD Pattern: No Length Limits

```pseudocode
// VULNERABLE: No length limits - DoS possible

FUNCTION create_post(request):
    title = request.body.title    // Could be 1GB!
    content = request.body.content
    database.insert("posts", {title, content})
END FUNCTION
```

## GOOD Pattern: Enforce Length Limits

```pseudocode
// SECURE: Length limits on all inputs

CONSTANT MAX_TITLE = 200
CONSTANT MAX_CONTENT = 50000

FUNCTION create_post(request):
    title = request.body.title
    content = request.body.content

    IF title.length > MAX_TITLE:
        THROW ValidationError("Title exceeds " + MAX_TITLE + " characters")
    END IF
    IF content.length > MAX_CONTENT:
        THROW ValidationError("Content exceeds " + MAX_CONTENT + " characters")
    END IF

    database.insert("posts", {title, content})
END FUNCTION
```

## Validation Checklist

| Check | Example |
|-------|---------|
| Type | `typeof(value) == "string"` |
| Length | `value.length <= 200` |
| Format | `regex.match(pattern, value)` |
| Range | `value >= 0 AND value <= 100` |
| Allowlist | `value IN allowed_values` |
| Required | `value IS NOT NULL` |

## Detection

- Look for request parameters used without validation
- Search for client-side validation without server-side equivalent
- Check for missing type assertions on input data
- Review for absent length limits on strings and arrays

## Prevention Checklist

- [ ] Validate ALL input server-side (client-side is UX only)
- [ ] Check type, length, format, and range for every input
- [ ] Use schema validation libraries for complex structures
- [ ] Set maximum length limits to prevent DoS
- [ ] Use allowlists over denylists when possible
- [ ] Configure request body size limits at framework level

## Related Patterns

- [sql-injection](../sql-injection/) - Enabled by missing validation
- [xss](../xss/) - Enabled by missing validation
- [path-traversal](../path-traversal/) - Enabled by missing validation

## References

- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
