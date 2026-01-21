---
name: ldap-injection-anti-pattern
description: Security anti-pattern for LDAP injection vulnerabilities (CWE-90). Use when generating or reviewing code that constructs LDAP filters, queries directory services, or handles user input in LDAP operations. Detects unescaped special characters in LDAP filters.
---

# LDAP Injection Anti-Pattern

**Severity:** High

## Risk

LDAP injection allows attackers to modify LDAP queries by injecting special characters, potentially bypassing authentication or accessing unauthorized data. This can lead to:

- Authentication bypass
- Unauthorized data access
- Information disclosure about directory structure
- Privilege escalation

## BAD Pattern

```pseudocode
// VULNERABLE: Unescaped LDAP filters

FUNCTION find_user_by_name(username):
    // User input directly in LDAP filter
    filter = "(uid=" + username + ")"
    RETURN ldap.search("ou=users,dc=example,dc=com", filter)
END FUNCTION

FUNCTION authenticate_ldap(username, password):
    // Both fields injectable
    filter = "(&(uid=" + username + ")(userPassword=" + password + "))"
    results = ldap.search(BASE_DN, filter)
    RETURN results.count > 0
END FUNCTION

// Attack: username = "*)(uid=*))(|(uid=*"
// Result: (uid=*)(uid=*))(|(uid=*)
// This can return all users or bypass authentication

// Attack: username = "*"
// Result: (uid=*) - matches all users
```

## GOOD Pattern

```pseudocode
// SECURE: Escape LDAP special characters

FUNCTION escape_ldap(input):
    // Escape LDAP special characters: * ( ) \ NUL
    result = input
    result = result.replace("\\", "\\5c")  // Backslash first!
    result = result.replace("*", "\\2a")
    result = result.replace("(", "\\28")
    result = result.replace(")", "\\29")
    result = result.replace("\0", "\\00")
    RETURN result
END FUNCTION

FUNCTION find_user_by_name(username):
    // Input is escaped before use
    safe_username = escape_ldap(username)
    filter = "(uid=" + safe_username + ")"
    RETURN ldap.search("ou=users,dc=example,dc=com", filter)
END FUNCTION

FUNCTION authenticate_ldap(username, password):
    // Better: Use LDAP bind for authentication instead of filter
    user_dn = "uid=" + escape_ldap(username) + ",ou=users,dc=example,dc=com"

    TRY:
        connection = ldap.bind(user_dn, password)
        connection.close()
        RETURN TRUE
    CATCH LDAPError:
        RETURN FALSE
    END TRY
END FUNCTION
```

## LDAP Special Characters

Characters that must be escaped in LDAP filters:

| Character | Hex Escape |
|-----------|------------|
| `*` | `\2a` |
| `(` | `\28` |
| `)` | `\29` |
| `\` | `\5c` |
| `NUL` | `\00` |

## Detection

- Look for string concatenation in LDAP filter construction
- Search for `ldap.search()`, `ldap.filter()`, or similar calls with user input
- Check for unescaped `*`, `(`, `)`, or `\` in filter strings
- Review authentication code that uses LDAP filters instead of bind

## Prevention Checklist

- [ ] Escape all LDAP special characters in user input
- [ ] Use LDAP bind for authentication instead of search filters
- [ ] Validate input against allowlist of expected characters
- [ ] Use parameterized LDAP queries if your library supports them
- [ ] Apply principle of least privilege to LDAP service accounts

## Related Patterns

- [sql-injection](../sql-injection/) - Similar injection pattern for databases
- [xpath-injection](../xpath-injection/) - Similar injection for XML queries
- [missing-authentication](../missing-authentication/) - Often the target of LDAP injection

## References

- [OWASP Top 10 A05:2025 - Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)
- [OWASP LDAP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html)
- [CWE-90: LDAP Injection](https://cwe.mitre.org/data/definitions/90.html)
- [CAPEC-136: LDAP Injection](https://capec.mitre.org/data/definitions/136.html)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
