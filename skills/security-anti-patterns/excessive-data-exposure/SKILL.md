---
name: excessive-data-exposure-anti-pattern
description: Security anti-pattern for excessive data exposure (CWE-200). Use when generating or reviewing API responses, database queries, or data serialization. Detects returning more data than necessary including internal fields, sensitive attributes, and related records.
---

# Excessive Data Exposure Anti-Pattern

**Severity:** High

## Risk

APIs that return entire database objects expose sensitive fields that clients don't need:

- Internal IDs and implementation details
- Password hashes and security tokens
- PII (emails, addresses, phone numbers)
- Related records with sensitive data
- Admin-only fields

## BAD Pattern: Return Entire Objects

```pseudocode
// VULNERABLE: Returns all database fields

FUNCTION get_user(request):
    user_id = request.params.id
    user = database.find_user(user_id)

    // Returns EVERYTHING including sensitive fields
    RETURN user

    // Response includes:
    // {
    //   id: 123,
    //   username: "john",
    //   email: "john@example.com",
    //   password_hash: "$2b$12$...",  // Exposed!
    //   ssn: "123-45-6789",           // Exposed!
    //   created_at: "...",
    //   internal_notes: "...",         // Exposed!
    //   api_key: "sk_..."              // Exposed!
    // }
END FUNCTION

FUNCTION list_orders(request):
    orders = database.query("SELECT * FROM orders")
    // Returns all fields from all related tables
    RETURN orders.with_relations(["user", "payments", "shipping"])
END FUNCTION
```

## GOOD Pattern: DTOs with Explicit Fields

```pseudocode
// SECURE: Return only needed fields via DTO

CLASS UserPublicDTO:
    FIELDS: id, username, avatar_url, created_at

    FUNCTION from_user(user):
        RETURN new UserPublicDTO({
            id: user.id,
            username: user.username,
            avatar_url: user.avatar_url,
            created_at: user.created_at
        })
    END FUNCTION
END CLASS

CLASS UserPrivateDTO:  // For user viewing their own profile
    FIELDS: id, username, email, avatar_url, created_at

    FUNCTION from_user(user):
        RETURN new UserPrivateDTO({
            id: user.id,
            username: user.username,
            email: user.email,
            avatar_url: user.avatar_url,
            created_at: user.created_at
        })
    END FUNCTION
END CLASS

FUNCTION get_user(request):
    user_id = request.params.id
    user = database.find_user(user_id)
    current_user = request.authenticated_user

    // Return appropriate DTO based on who's asking
    IF current_user.id == user_id:
        RETURN UserPrivateDTO.from_user(user)
    ELSE:
        RETURN UserPublicDTO.from_user(user)
    END IF
END FUNCTION
```

## BAD Pattern: Filtering Client-Side

```pseudocode
// VULNERABLE: Sending all data, expecting client to filter

FUNCTION get_users_admin(request):
    users = database.get_all_users()

    // Returns all users with all fields
    // "Client will only show what it needs"
    RETURN users

    // Problem: Attacker intercepts response and gets everything
END FUNCTION
```

## GOOD Pattern: Server-Side Filtering

```pseudocode
// SECURE: Only return permitted fields

FUNCTION get_users_admin(request):
    current_user = request.authenticated_user

    // Check authorization
    IF NOT current_user.is_admin:
        RETURN error_response(403, "Admin access required")
    END IF

    // Query only needed fields
    users = database.query(
        "SELECT id, username, email, role, created_at FROM users"
    )

    // Transform to DTOs
    RETURN users.map(u => UserAdminDTO.from_user(u))
END FUNCTION
```

## Field Visibility Matrix

| Field | Public | Authenticated | Admin |
|-------|--------|---------------|-------|
| `id` | Yes | Yes | Yes |
| `username` | Yes | Yes | Yes |
| `email` | No | Own only | Yes |
| `password_hash` | No | No | No |
| `api_key` | No | Own only | No |
| `internal_notes` | No | No | Yes |
| `ssn` | No | No | No |

## Detection

- Look for `SELECT *` in database queries
- Search for returning raw model objects in API responses
- Check for `.to_json()` or `.serialize()` on full models
- Review responses for sensitive field names

## Prevention Checklist

- [ ] Use DTOs/ViewModels with explicit field allowlists
- [ ] Never return raw database objects
- [ ] Select only needed columns in queries
- [ ] Implement field-level authorization
- [ ] Review API responses for sensitive data
- [ ] Use different DTOs for different access levels
- [ ] Filter on server, not client

## Related Patterns

- [missing-authentication](../missing-authentication/) - Access control
- [mass-assignment](../mass-assignment/) - Inverse problem (input)

## References

- [OWASP Top 10 A01:2025 - Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/)
- [OWASP API Security API3:2023 - Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)
- [CWE-200: Information Exposure](https://cwe.mitre.org/data/definitions/200.html)
- [CAPEC-37: Retrieve Embedded Sensitive Data](https://capec.mitre.org/data/definitions/37.html)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
