---
name: type-confusion-anti-pattern
description: Security anti-pattern for type confusion vulnerabilities (CWE-843). Use when generating or reviewing code in dynamic languages that compares values, processes JSON/user input, or uses loose equality. Detects weak typing exploits and type coercion attacks.
---

# Type Confusion Anti-Pattern

**Severity:** High

## Risk

Type confusion occurs when applications use loose type comparisons or fail to validate input types, allowing attackers to bypass security checks. Dynamic languages like JavaScript and PHP are especially vulnerable. This leads to:

- Authentication bypass
- Authorization bypass
- NoSQL injection through type manipulation
- Magic hash comparisons (0e attack)
- Array/object confusion in queries

## BAD Pattern: Loose Equality Comparison

```pseudocode
// VULNERABLE: PHP/JavaScript style loose comparison

FUNCTION vulnerable_auth(password):
    stored_hash = "0e123456789"  // Some MD5 hashes start with "0e"
    input_hash = md5(password)

    // In PHP: "0e123456789" == "0e987654321" is TRUE!
    // Both are interpreted as 0 * 10^(number) = 0
    IF input_hash == stored_hash:  // Loose comparison
        RETURN "Authenticated"
    END IF
    RETURN "Failed"
END FUNCTION

// Attack: Find any password that hashes to "0e..." pattern
// "240610708" -> md5 = "0e462097431906509019562988736854"
// This equals "0" in loose comparison, matching any 0e hash
```

## BAD Pattern: Type Confusion in Database Queries

```pseudocode
// VULNERABLE: MongoDB/NoSQL injection via type confusion

FUNCTION vulnerable_password_reset(token):
    // Expected: token = "abc123def456" (string)
    // Attack: token = {"$gt": ""} (object)

    result = database.find_one({"resetToken": token})
    // Query becomes: {resetToken: {"$gt": ""}}
    // This matches ANY non-empty token!

    IF result:
        RETURN "Token valid"
    END IF
    RETURN "Invalid token"
END FUNCTION

// Attack payload (JSON):
// {"token": {"$ne": null}}  -- matches any non-null token
// {"token": {"$gt": ""}}    -- matches any string token
```

## BAD Pattern: Array Instead of String

```pseudocode
// VULNERABLE: Array bypasses string validation

FUNCTION vulnerable_username_check(username):
    // Expected: username = "admin"
    // Attack: username = ["admin"]

    IF username != "admin":  // Array != string, comparison fails
        RETURN "OK"
    END IF
    RETURN "Reserved username"
END FUNCTION

// Later in code:
FUNCTION create_user(username):
    // Array might be converted to string "admin" or cause other issues
    query = "INSERT INTO users (name) VALUES (?)"
    database.execute(query, [username])  // What happens with array?
END FUNCTION
```

## GOOD Pattern: Strict Type Checking

```pseudocode
// SECURE: Always check types explicitly

FUNCTION secure_auth(password):
    stored_hash = get_stored_hash(user)
    input_hash = hash_password(password)

    // Strict type check first
    IF typeof(input_hash) != "string" OR typeof(stored_hash) != "string":
        RETURN "Failed"
    END IF

    // Then constant-time comparison
    IF NOT constant_time_equals(input_hash, stored_hash):
        RETURN "Failed"
    END IF

    RETURN "Authenticated"
END FUNCTION
```

## GOOD Pattern: Validate Input Types

```pseudocode
// SECURE: Explicit type validation for all inputs

FUNCTION secure_password_reset(token):
    // Enforce string type
    IF typeof(token) != "string":
        RETURN {valid: FALSE, error: "Invalid token format"}
    END IF

    // Validate format (alphanumeric, specific length)
    IF NOT regex.match("^[a-f0-9]{64}$", token):
        RETURN {valid: FALSE, error: "Invalid token format"}
    END IF

    // Now safe to query
    result = database.find_one({"resetToken": token})
    IF result:
        RETURN {valid: TRUE, user: result.user_id}
    END IF
    RETURN {valid: FALSE, error: "Token not found"}
END FUNCTION
```

## GOOD Pattern: Schema Validation

```pseudocode
// SECURE: Use schema validation for complex inputs

SCHEMA UserInput:
    username: String, required, min_length=3, max_length=30
    email: String, required, format=email
    age: Integer, optional, min=0, max=150

FUNCTION create_user(request):
    // Schema validation enforces types
    TRY:
        validated = UserInput.validate(request.body)
    CATCH ValidationError AS e:
        RETURN {error: e.message}
    END TRY

    // All fields are now correct types
    // validated.username is definitely a string
    // validated.age is definitely an integer (or null)
    create_user_in_db(validated)
END FUNCTION
```

## Type Confusion Examples by Language

| Language | Attack | Vulnerable Pattern |
|----------|--------|-------------------|
| PHP | `"0e123" == "0e456"` | Loose comparison |
| JavaScript | `[] == false` | Loose comparison |
| PHP | `strcmp([], "a")` | Returns NULL (falsy) |
| MongoDB | `{"$gt": ""}` | Operator injection |
| Python | `"123" == 123` | False, but implicit conversion elsewhere |

## Detection

- Search for `==` instead of `===` in JavaScript/PHP
- Look for JSON input used directly in database queries
- Check for missing type validation on API inputs
- Review strcmp/string comparisons with user input
- Test by sending arrays, objects, numbers where strings expected

## Prevention Checklist

- [ ] Use strict equality (`===`) in JavaScript
- [ ] Use strict comparison (`===`) in PHP or type-safe functions
- [ ] Validate input types before any processing
- [ ] Use schema validation for API inputs
- [ ] Sanitize MongoDB queries (don't allow operators from user input)
- [ ] Be explicit about expected types in function signatures
- [ ] Test with wrong types (array, object, number, boolean)

## Related Patterns

- [missing-input-validation](../missing-input-validation/) - Type is part of validation
- [sql-injection](../sql-injection/) - NoSQL type confusion is similar
- [encoding-bypass](../encoding-bypass/) - Related input manipulation

## References

- [OWASP Top 10 A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [CWE-843: Access of Resource Using Incompatible Type](https://cwe.mitre.org/data/definitions/843.html)
- [CAPEC-153: Input Data Manipulation](https://capec.mitre.org/data/definitions/153.html)
- [PHP Type Juggling](https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf)
- [NoSQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
