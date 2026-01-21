---
name: "second-order-injection-anti-pattern"
description: "Security anti-pattern for second-order injection vulnerabilities (CWE-89 variant). Use when generating or reviewing code that retrieves data from databases, caches, or storage and uses it in subsequent queries or commands. Detects trusted internal data used unsafely."
---

# Second-Order Injection Anti-Pattern

**Severity:** High

## Summary

Second-order injection (also known as "stored injection") is a type of injection vulnerability where a malicious payload is first stored in a trusted data store (like a database or log file) and then retrieved and executed later in an insecure context. The initial storage might appear secure because the data is properly parameterized or escaped when it's first saved. However, when the data is later retrieved and used in a dynamic query or command without re-sanitization, the malicious payload is activated. This makes second-order injection particularly insidious and difficult to detect, as the injection point and the execution point are separated in time and often in different parts of the codebase.

## The Anti-Pattern

The anti-pattern is treating data retrieved from a "trusted" source (like your own database) as inherently safe, and then using it in a dynamic query or command without proper re-sanitization or parameterization.

### BAD Code Example

```python
# VULNERABLE: Data is stored safely, but later retrieved and used unsafely.
import sqlite3

db = sqlite3.connect("app.db")
db.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
db.execute("CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY, action TEXT, user_email TEXT)")

# Step 1: User Registration (Appears Safe)
def register_user(name, email):
    # This uses a parameterized query, so it's safe against direct SQL injection.
    # Attacker's email input: "bad@example.com' UNION SELECT password FROM users -- "
    # This input is safely stored as a string in the 'email' column.
    db.execute("INSERT INTO users (name, email) VALUES (?, ?)", (name, email))
    db.commit()

# Step 2: Logging User Action (Later Use - VULNERABLE)
def log_user_action(user_id, action):
    # Retrieve user email from the database.
    cursor = db.execute("SELECT email FROM users WHERE id = ?", (user_id,))
    user_email = cursor.fetchone()[0] # Assume we get "bad@example.com' UNION SELECT password FROM users -- "

    # CRITICAL FLAW: The user_email is now concatenated into a new SQL query for logging.
    # The application "trusts" the data because it came from its own database.
    log_query = f"INSERT INTO logs (action, user_email) VALUES ('{action}', '{user_email}')"

    # The final query becomes:
    # INSERT INTO logs (action, user_email) VALUES ('view_profile', 'bad@example.com' UNION SELECT password FROM users -- ')
    # The attacker's injected SQL now runs, potentially exposing passwords or other sensitive data from the 'users' table.
    db.execute(log_query)
    db.commit()

# Scenario:
# 1. Attacker registers with a specially crafted email.
# 2. Attacker performs an action that triggers the logging function.
# 3. The malicious payload in the email is executed in the logging query.
```

### GOOD Code Example

```python
# SECURE: All data used in SQL queries is parameterized, regardless of its source.
import sqlite3

db = sqlite3.connect("app_safe.db")
db.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
db.execute("CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY, action TEXT, user_email TEXT)")

# Step 1: User Registration (Safe)
def register_user_safe(name, email):
    db.execute("INSERT INTO users (name, email) VALUES (?, ?)", (name, email))
    db.commit()

# Step 2: Logging User Action (Also Safe)
def log_user_action_safe(user_id, action):
    cursor = db.execute("SELECT email FROM users WHERE id = ?", (user_id,))
    user_email = cursor.fetchone()[0]

    # SECURE: Even though `user_email` came from the database, it is still treated
    # as untrusted input and passed as a parameter to the INSERT query.
    db.execute("INSERT INTO logs (action, user_email) VALUES (?, ?)", (action, user_email))
    db.commit()
```

## Detection

- **Audit data flows:** Systematically track data from its entry point (user input) through its storage and subsequent retrieval and use.
- **Identify dynamic query/command construction:** Look for any code that builds SQL queries, shell commands, or other interpretive language statements by concatenating strings that include variables whose values originated from user input, even if they were stored in a database.
- **Review stored procedures:** If your application uses stored procedures, examine their definitions for any dynamic SQL that might use input parameters without proper escaping or parameterization.
- **Consider background jobs/asynchronous tasks:** Pay special attention to components that process data in the background, as they might retrieve stored data and use it in new, insecure contexts.

## Prevention

- [ ] **Parameterize all queries:** This is the most crucial defense. Always use parameterized queries or prepared statements for *all* database interactions, regardless of whether the data comes directly from user input or from your own database.
- [ ] **Never trust data:** Data retrieved from your own database, cache, or any other internal store should still be considered "tainted" if its ultimate origin was untrusted user input. Apply the same validation and sanitization rules as if it were fresh input.
- [ ] **Use ORMs (Object-Relational Mappers) consistently:** When used correctly, ORMs help prevent injection by automatically parameterizing queries. Ensure you're not using any "raw query" features of your ORM that might bypass its built-in protections.
- [ ] **Sanitize output before display:** While not directly preventing second-order injection, it's a good practice to escape data before rendering it in HTML or other contexts to prevent XSS.

## Related Security Patterns & Anti-Patterns

- [SQL Injection Anti-Pattern](../sql-injection/): Second-order SQL injection is a variant of this fundamental vulnerability.
- [Command Injection Anti-Pattern](../command-injection/): Similar second-order risks exist when data stored safely is later used in an insecure shell command.
- [Log Injection Anti-Pattern](../log-injection/): Log files can be a vector for second-order attacks if logged data is later used in an insecure context (e.g., parsing logs with a vulnerable regex).

## References

- [OWASP Top 10 A05:2025 - Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)
- [OWASP GenAI LLM01:2025 - Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [OWASP API Security API8:2023 - Security Misconfiguration](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/)
- [OWASP Second Order SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)
- [CAPEC-66: SQL Injection](https://capec.mitre.org/data/definitions/66.html)
- [PortSwigger: Sql Injection](https://portswigger.net/web-security/sql-injection)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
