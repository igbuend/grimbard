---
name: mass-assignment-anti-pattern
description: Security anti-pattern for mass assignment vulnerabilities (CWE-915). Use when generating or reviewing code that creates or updates objects from user input, form handling, or API request processing. Detects uncontrolled property binding enabling privilege escalation.
---

# Mass Assignment Anti-Pattern

**CWE:** CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)
**CAPEC:** [CAPEC-114: Authentication Abuse](https://capec.mitre.org/data/definitions/114.html)
**Severity:** High
**OWASP:** A01:2021 - Broken Access Control

## Risk

Mass assignment allows attackers to modify object properties they shouldn't have access to by adding extra fields to requests:

- Privilege escalation (setting `is_admin: true`)
- Price manipulation (setting `price: 0`)
- Account takeover (changing `user_id` or `email`)
- Bypassing business logic

## BAD Pattern: Direct Object Assignment

```pseudocode
// VULNERABLE: All request fields assigned to object

FUNCTION create_user(request):
    // Attacker sends: {"username": "john", "is_admin": true}
    user = new User(request.body)  // is_admin gets set!
    database.save(user)
    RETURN user
END FUNCTION

FUNCTION update_order(request):
    order_id = request.params.id
    order = database.find_order(order_id)

    // Attacker sends: {"status": "shipped", "total_price": 0}
    order.update(request.body)  // Price modified!
    database.save(order)
    RETURN order
END FUNCTION
```

## GOOD Pattern: Explicit Field Allowlist

```pseudocode
// SECURE: Only allowed fields can be set

CONSTANT USER_ALLOWED_FIELDS = ["username", "email", "password", "avatar"]
CONSTANT ORDER_UPDATE_FIELDS = ["shipping_address", "notes"]

FUNCTION create_user(request):
    // Only pick allowed fields
    user_data = pick(request.body, USER_ALLOWED_FIELDS)

    // Explicitly set defaults for sensitive fields
    user = new User(user_data)
    user.is_admin = FALSE  // Always false on creation
    user.role = "user"     // Always default role

    database.save(user)
    RETURN user
END FUNCTION

FUNCTION update_order(request):
    order_id = request.params.id
    order = database.find_order(order_id)

    // Authorization check
    IF order.user_id != request.authenticated_user.id:
        RETURN error_response(403, "Not your order")
    END IF

    // Only allow specific fields to be updated
    update_data = pick(request.body, ORDER_UPDATE_FIELDS)
    order.update(update_data)

    database.save(order)
    RETURN order
END FUNCTION

FUNCTION pick(object, allowed_keys):
    result = {}
    FOR key IN allowed_keys:
        IF key IN object:
            result[key] = object[key]
        END IF
    END FOR
    RETURN result
END FUNCTION
```

## BAD Pattern: Blocklist Approach

```pseudocode
// VULNERABLE: Blocklist is incomplete and error-prone

CONSTANT BLOCKED_FIELDS = ["is_admin", "role"]

FUNCTION update_user(request):
    // New sensitive fields get forgotten
    // What about: "admin", "administrator", "isAdmin", "permissions"?
    update_data = omit(request.body, BLOCKED_FIELDS)
    user.update(update_data)
END FUNCTION
```

## GOOD Pattern: Strong Typing with DTOs

```pseudocode
// SECURE: DTOs define exactly what can be set

CLASS CreateUserDTO:
    FIELDS:
        username: String, required, max_length=50
        email: String, required, format=email
        password: String, required, min_length=12

    // No is_admin, role, or other sensitive fields
END CLASS

CLASS UpdateUserDTO:
    FIELDS:
        email: String, optional, format=email
        avatar_url: String, optional, format=url

    // Cannot update username, role, etc.
END CLASS

FUNCTION create_user(request):
    // Validate and parse only defined fields
    dto = CreateUserDTO.parse(request.body)

    user = new User()
    user.username = dto.username
    user.email = dto.email
    user.password_hash = bcrypt.hash(dto.password)
    user.is_admin = FALSE  // Set explicitly
    user.role = "user"     // Set explicitly

    database.save(user)
    RETURN UserResponseDTO.from(user)
END FUNCTION
```

## Common Mass Assignment Targets

| Field | Attack |
|-------|--------|
| `is_admin`, `admin`, `role` | Privilege escalation |
| `price`, `amount`, `total` | Financial manipulation |
| `user_id`, `owner_id` | Ownership takeover |
| `verified`, `active` | Status bypass |
| `created_at`, `updated_at` | Log tampering |
| `password_hash` | Direct password change |

## Detection

- Look for `Model(request.body)` or `Model(**request)` patterns
- Search for `.update(request.body)` or `.assign(params)`
- Check for missing field allowlists in create/update operations
- Review for blocklist approaches (omit instead of pick)

## Prevention Checklist

- [ ] Use explicit field allowlists (never blocklists)
- [ ] Define DTOs for each create/update operation
- [ ] Set sensitive fields explicitly in code
- [ ] Use strong typing to define allowed properties
- [ ] Validate input against schema before assignment
- [ ] Different DTOs for different user roles

## Related Patterns

- [excessive-data-exposure](../excessive-data-exposure/) - Output equivalent
- [missing-authentication](../missing-authentication/) - Authorization checks

## References

- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
- [CWE-915: Mass Assignment](https://cwe.mitre.org/data/definitions/915.html)
- [OWASP Mass Assignment](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
