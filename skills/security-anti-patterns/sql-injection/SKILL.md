---
name: sql-injection-anti-pattern
description: Security anti-pattern for SQL injection vulnerabilities (CWE-89). Use when generating or reviewing code that constructs database queries, builds SQL statements, or handles user input in database operations. Detects string concatenation in queries and recommends parameterized queries.
---

# SQL Injection Anti-Pattern

**CWE:** CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)
**CAPEC:** [CAPEC-66: SQL Injection](https://capec.mitre.org/data/definitions/66.html)
**Severity:** Critical
**OWASP:** A03:2021 - Injection

## Risk

SQL injection allows attackers to execute arbitrary SQL commands by manipulating user input. AI models frequently generate vulnerable string concatenation patterns from training data containing millions of insecure examples. SQL injection can lead to:

- Complete database access and data exfiltration
- Authentication bypass
- Data modification or deletion
- In some cases, remote code execution

## BAD Pattern

```pseudocode
// VULNERABLE: String concatenation in SQL queries

FUNCTION get_user(username):
    // User input directly concatenated into query
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    RETURN database.execute(query)
END FUNCTION

FUNCTION search_products(category, min_price):
    // Multiple injection points
    query = "SELECT * FROM products WHERE category = '" + category +
            "' AND price > " + min_price
    RETURN database.execute(query)
END FUNCTION

// Attack: username = "admin' OR '1'='1' --"
// Result: SELECT * FROM users WHERE username = 'admin' OR '1'='1' --'
// This bypasses authentication and returns all users
```

## GOOD Pattern

```pseudocode
// SECURE: Parameterized queries (prepared statements)

FUNCTION get_user(username):
    // Parameters are escaped automatically by the database driver
    query = "SELECT * FROM users WHERE username = ?"
    RETURN database.execute(query, [username])
END FUNCTION

FUNCTION search_products(category, min_price):
    // All parameters bound separately
    query = "SELECT * FROM products WHERE category = ? AND price > ?"
    RETURN database.execute(query, [category, min_price])
END FUNCTION

// With named parameters (preferred for clarity)
FUNCTION get_user_named(username):
    query = "SELECT * FROM users WHERE username = :username"
    RETURN database.execute(query, {username: username})
END FUNCTION
```

## Detection

- Look for string concatenation (`+`, `||`, `concat()`, f-strings, template literals) in SQL queries
- Search for `execute()`, `query()`, or `raw()` calls with string variables
- Check for `.format()`, `%s`, or `${}` in SQL strings
- Review any code that builds SQL dynamically based on user input

## Prevention Checklist

- [ ] Use parameterized queries or prepared statements for all database operations
- [ ] Never concatenate user input directly into SQL strings
- [ ] Use an ORM with proper escaping when possible
- [ ] Apply principle of least privilege to database accounts
- [ ] Validate and sanitize input as defense in depth (not primary defense)

## Related Patterns

- [command-injection](../command-injection/) - Similar injection pattern for shell commands
- [ldap-injection](../ldap-injection/) - Injection in LDAP queries
- [xpath-injection](../xpath-injection/) - Injection in XML queries
- [missing-input-validation](../missing-input-validation/) - Root cause enabler

## References

- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
