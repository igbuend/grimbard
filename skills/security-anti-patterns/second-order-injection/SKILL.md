---
name: second-order-injection-anti-pattern
description: Security anti-pattern for second-order injection vulnerabilities (CWE-89 variant). Use when generating or reviewing code that retrieves data from databases, caches, or storage and uses it in subsequent queries or commands. Detects trusted internal data used unsafely.
---

# Second-Order Injection Anti-Pattern

**Severity:** High

## Risk

Second-order injection occurs when data is stored safely but used unsafely later. The initial storage uses parameterized queries (safe), but subsequent code retrieves and uses that data in dynamic queries (unsafe). This leads to:

- Delayed exploitation (attack payload triggers later)
- Bypassing input validation (data comes from "trusted" database)
- Difficult detection (initial storage looks secure)
- Background job compromise

## BAD Pattern: Stored Data Used Unsafely

```pseudocode
// VULNERABLE: Data stored safely but used unsafely later

// Step 1: User creates profile (looks safe)
FUNCTION create_profile(user_id, display_name):
    // Parameterized - SAFE for initial storage
    query = "INSERT INTO profiles (user_id, display_name) VALUES (?, ?)"
    database.execute(query, [user_id, display_name])
    // Attacker sets display_name = "admin'--"
END FUNCTION

// Step 2: Background job uses stored data UNSAFELY
FUNCTION generate_report_for_user(user_id):
    // Get the stored display name
    profile = database.execute("SELECT display_name FROM profiles WHERE user_id = ?", [user_id])
    display_name = profile.display_name
    // "admin'--" retrieved from database

    // VULNERABLE: Trusting data from database
    report_query = "INSERT INTO reports (title) VALUES ('Report for " + display_name + "')"
    database.execute(report_query)
    // Result: INSERT INTO reports (title) VALUES ('Report for admin'--')
END FUNCTION
```

## BAD Pattern: Stored Procedure with Dynamic SQL

```pseudocode
// VULNERABLE: Dynamic SQL inside stored procedure

// Stored Procedure Definition (in database)
CREATE PROCEDURE search_users(search_term VARCHAR(100))
BEGIN
    // VULNERABLE: Dynamic SQL construction
    SET @query = CONCAT('SELECT * FROM users WHERE name LIKE ''%', search_term, '%''');
    PREPARE stmt FROM @query;
    EXECUTE stmt;
END

// Application code looks safe...
FUNCTION search_users(term):
    RETURN database.call_procedure("search_users", [term])
    // But injection still occurs inside the procedure!
END FUNCTION
```

## GOOD Pattern: Parameterize All Queries

```pseudocode
// SECURE: Parameterize ALL queries, even with "internal" data

FUNCTION generate_report_for_user_safe(user_id):
    profile = database.execute("SELECT display_name FROM profiles WHERE user_id = ?", [user_id])

    // Still parameterize even though data is from database
    report_query = "INSERT INTO reports (title) VALUES (?)"
    title = "Report for " + profile.display_name
    database.execute(report_query, [title])
END FUNCTION

// SECURE: Parameterized stored procedures
CREATE PROCEDURE search_users_safe(search_term VARCHAR(100))
BEGIN
    // Use parameterization within procedure
    SELECT * FROM users WHERE name LIKE CONCAT('%', search_term, '%');
    // Or use prepared statement properly
    SET @query = 'SELECT * FROM users WHERE name LIKE ?';
    SET @search = CONCAT('%', search_term, '%');
    PREPARE stmt FROM @query;
    EXECUTE stmt USING @search;
END
```

## Common Second-Order Scenarios

| Scenario | Initial Store | Later Use |
|----------|---------------|-----------|
| User profile | Safe INSERT | Unsafe report generation |
| Log entries | Safe log write | Unsafe log analysis query |
| Configuration | Safe config save | Unsafe dynamic query building |
| Cached data | Safe cache write | Unsafe cache value interpolation |
| Message queues | Safe enqueue | Unsafe message processing |

## Detection

- Audit all code paths where database data is used in subsequent queries
- Search for string concatenation using variables retrieved from database
- Review stored procedures for dynamic SQL construction
- Check background jobs and scheduled tasks for query building
- Look for patterns where "internal" or "trusted" data sources are used in queries

## Prevention Checklist

- [ ] Parameterize ALL queries, including those using data from databases
- [ ] Never trust data just because it came from your own database
- [ ] Review stored procedures for dynamic SQL construction
- [ ] Audit background jobs and async processors for injection points
- [ ] Apply the same injection defenses to internal data flows
- [ ] Use ORMs consistently throughout the application

## Related Patterns

- [sql-injection](../sql-injection/) - Primary injection pattern
- [command-injection](../command-injection/) - Similar second-order risks
- [log-injection](../log-injection/) - Log data can be second-order source

## References

- [OWASP Top 10 A05:2025 - Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)
- [OWASP Second Order SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CAPEC-66: SQL Injection](https://capec.mitre.org/data/definitions/66.html)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
