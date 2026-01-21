---
name: "ldap-injection-anti-pattern"
description: "Security anti-pattern for LDAP injection vulnerabilities (CWE-90). Use when generating or reviewing code that constructs LDAP filters, queries directory services, or handles user input in LDAP operations. Detects unescaped special characters in LDAP filters."
---

# LDAP Injection Anti-Pattern

**Severity:** High

## Summary

LDAP Injection is a vulnerability that occurs when user-provided input is insecurely inserted into an LDAP (Lightweight Directory Access Protocol) query. Similar to SQL injection, it allows an attacker to manipulate the query's logic by injecting special characters. A successful attack can lead to authentication bypass, unauthorized data access, privilege escalation, or disclosure of the directory service's structure.

## The Anti-Pattern

The anti-pattern is building LDAP filters by directly concatenating unescaped user input. The special characters in the input can alter the structure of the LDAP filter, changing its intended meaning.

### BAD Code Example

```python
# VULNERABLE: Unescaped user input is concatenated into an LDAP filter.
import ldap

def find_user_by_name(ldap_connection, username):
    # The username is directly inserted into the filter string.
    # An attacker can inject special LDAP characters like '*', '(', ')', or '|'.
    search_filter = f"(uid={username})"

    # Attacker's input for `username`: 'admin*)(uid=*)'
    # The resulting filter becomes: '(uid=admin*)(uid=*)'
    # This can return unintended records or bypass security checks.
    try:
        results = ldap_connection.search_s(
            "ou=users,dc=example,dc=com",
            ldap.SCOPE_SUBTREE,
            search_filter
        )
        return results
    except ldap.LDAPError as e:
        print(f"LDAP search failed: {e}")
        return None
```

### GOOD Code Example

```python
# SECURE: Escape user input before including it in the filter.
import ldap
from ldap.filter import escape_filter_chars

def find_user_by_name_safe(ldap_connection, username):
    # All user-supplied input must be properly escaped to neutralize special characters.
    # The `ldap.filter.escape_filter_chars` function handles this securely.
    safe_username = escape_filter_chars(username)
    search_filter = f"(uid={safe_username})"

    # If the attacker tries the same input ('admin*)(uid=*)'), the escaped filter
    # will become: '(uid=admin\2a\28uid=\2a\29)'
    # This will search for a user with that literal, harmless name.
    try:
        results = ldap_connection.search_s(
            "ou=users,dc=example,dc=com",
            ldap.SCOPE_SUBTREE,
            search_filter
        )
        return results
    except ldap.LDAPError as e:
        print(f"LDAP search failed: {e}")
        return None

# For authentication, it's even better to avoid search filters entirely and use the BIND operation.
def authenticate_ldap_safe(username, password):
    safe_username = escape_filter_chars(username)
    user_dn = f"uid={safe_username},ou=users,dc=example,dc=com"
    try:
        # Attempt to bind to the directory as the user.
        # This is the standard, secure way to verify credentials.
        conn = ldap.initialize("ldap://ldap.example.com")
        conn.simple_bind_s(user_dn, password)
        conn.unbind_s()
        return True # Bind successful, authentication passed.
    except ldap.INVALID_CREDENTIALS:
        return False # Bind failed, invalid credentials.
    except ldap.LDAPError as e:
        print(f"LDAP error: {e}")
        return False
```

## Detection

- **Review LDAP queries:** Look for any code that constructs LDAP search filters using string concatenation or formatting with user-controlled variables.
- **Check for escaping:** Ensure that any variable being inserted into an LDAP filter is first passed through a proper LDAP escaping function.
- **Search for LDAP query functions:** Identify all calls to functions like `ldap.search`, `search_s`, or similar methods in other languages, and trace the origin of the filter string.
- **Test with special characters:** Input LDAP metacharacters like `*`, `(`, `)`, `\`, and `|` to see if they alter the query's behavior or cause an error.

## Prevention

- [ ] **Always escape user input** before placing it in an LDAP filter. Use a trusted library function for this, such as `ldap.filter.escape_filter_chars` in Python.
- [ ] **Use the BIND operation for authentication** instead of performing a search and comparing passwords. Binding is the intended mechanism for verifying credentials in LDAP.
- [ ] **Use parameterized LDAP queries** if your library or framework supports them. This is the safest approach, as it separates the query structure from the data.
- [ ] **Apply the Principle of Least Privilege** to the LDAP service account, ensuring it has read-only access to only the necessary parts of the directory.

## Related Security Patterns & Anti-Patterns

- [SQL Injection Anti-Pattern](../sql-injection/): The same fundamental vulnerability of mixing code and data, but for SQL databases.
- [XPath Injection Anti-Pattern](../xpath-injection/): A similar injection vulnerability targeting XML databases.
- [Missing Input Validation Anti-Pattern](../missing-input-validation/): A root cause that enables many injection attacks.

## References

- [OWASP Top 10 A05:2025 - Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)
- [OWASP GenAI LLM01:2025 - Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [OWASP API Security API8:2023 - Security Misconfiguration](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/)
- [OWASP LDAP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html)
- [CWE-90: LDAP Injection](https://cwe.mitre.org/data/definitions/90.html)
- [CAPEC-136: LDAP Injection](https://capec.mitre.org/data/definitions/136.html)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
