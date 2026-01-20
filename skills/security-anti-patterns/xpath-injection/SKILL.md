---
name: xpath-injection-anti-pattern
description: Security anti-pattern for XPath injection vulnerabilities (CWE-643). Use when generating or reviewing code that queries XML documents, constructs XPath expressions, or handles user input in XML operations. Detects unescaped quotes and special characters in XPath queries.
---

# XPath Injection Anti-Pattern

**CWE:** CWE-643 (Improper Neutralization of Data within XPath Expressions)
**CAPEC:** [CAPEC-83: XPath Injection](https://capec.mitre.org/data/definitions/83.html)
**Severity:** High
**OWASP:** A03:2021 - Injection

## Risk

XPath injection allows attackers to manipulate XML queries by injecting special characters, potentially bypassing authentication or accessing unauthorized data. This can lead to:

- Authentication bypass
- Unauthorized data access
- Information disclosure
- XML data extraction

## BAD Pattern

```pseudocode
// VULNERABLE: Unescaped XPath queries

FUNCTION find_user_xml(username):
    // User input in XPath expression
    xpath = "//users/user[name='" + username + "']"
    RETURN xml_document.query(xpath)
END FUNCTION

FUNCTION authenticate_xml(username, password):
    // Both fields injectable
    xpath = "//users/user[name='" + username + "' and password='" + password + "']"
    result = xml_document.query(xpath)
    RETURN result IS NOT EMPTY
END FUNCTION

// Attack: username = "admin' or '1'='1"
// Result: //users/user[name='admin' or '1'='1']
// This returns all users, bypassing authentication

// Attack: username = "' or ''='"
// Result: //users/user[name='' or ''='']
// Always true condition
```

## GOOD Pattern

```pseudocode
// SECURE: Parameterized XPath or strict validation

// Option 1: Use parameterized XPath (if supported)
FUNCTION find_user_xml(username):
    xpath = "//users/user[name=$username]"
    RETURN xml_document.query(xpath, {username: username})
END FUNCTION

// Option 2: Escape XPath special characters
FUNCTION escape_xpath(input):
    // Handle quotes by splitting and concatenating
    IF input.contains("'") AND input.contains('"'):
        // Use concat() for strings with both quote types
        parts = input.split("'")
        escaped = "concat('" + parts.join("',\"'\",'" ) + "')"
        RETURN escaped
    ELSE IF input.contains("'"):
        RETURN '"' + input + '"'
    ELSE:
        RETURN "'" + input + "'"
    END IF
END FUNCTION

FUNCTION find_user_xml_escaped(username):
    // Validate input format first
    IF NOT is_valid_username(username):
        THROW Error("Invalid username format")
    END IF

    safe_username = escape_xpath(username)
    xpath = "//users/user[name=" + safe_username + "]"
    RETURN xml_document.query(xpath)
END FUNCTION

// Option 3: Strict whitelist validation
FUNCTION is_valid_username(username):
    // Only allow alphanumeric and limited special chars
    pattern = "^[a-zA-Z0-9_.-]{1,64}$"
    RETURN regex.match(pattern, username)
END FUNCTION
```

## Detection

- Look for string concatenation in XPath expression construction
- Search for `query()`, `evaluate()`, `selectNodes()`, or similar XPath calls with user input
- Check for unescaped single or double quotes in XPath strings
- Review XML processing code that uses user input in queries

## Prevention Checklist

- [ ] Use parameterized XPath queries when available
- [ ] Escape quotes and special characters in user input
- [ ] Validate input against strict allowlist patterns
- [ ] Consider using DOM traversal instead of XPath for simple lookups
- [ ] Limit XML document access to necessary data only

## Related Patterns

- [sql-injection](../sql-injection/) - Similar injection pattern for databases
- [ldap-injection](../ldap-injection/) - Similar injection for directory services
- [missing-input-validation](../missing-input-validation/) - Root cause enabler

## References

- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
- [CWE-643: XPath Injection](https://cwe.mitre.org/data/definitions/643.html)
- [OWASP XPath Injection](https://owasp.org/www-community/attacks/XPATH_Injection)
