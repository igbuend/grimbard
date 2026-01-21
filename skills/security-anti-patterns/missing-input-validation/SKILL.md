---
name: "missing-input-validation-anti-pattern"
description: "Security anti-pattern for missing input validation (CWE-20). Use when generating or reviewing code that processes user input, form data, API parameters, or external data. Detects client-only validation, missing type checks, and absent length limits. Foundation vulnerability enabling most attack classes."
---

# Missing Input Validation Anti-Pattern

**Severity:** High

## Summary

Missing input validation is one of the most common and fundamental security vulnerabilities. It occurs when an application fails to properly validate data received from a user or another external source before using it. This is the root cause of most major web application vulnerabilities, including SQL Injection, Cross-Site Scripting (XSS), Command Injection, and Path Traversal. An application must treat all incoming data as untrusted and validate it against a strict set of rules for type, length, format, and range.

## The Anti-Pattern

The anti-pattern is trusting any input from an external source without validating it on the server-side. This includes relying on client-side validation, which can be easily bypassed by an attacker.

### BAD Code Example

```python
# VULNERABLE: The application trusts user input completely, leading to SQL Injection.
from flask import request
import sqlite3

@app.route("/api/products")
def search_products():
    # The 'category' parameter is taken directly from the URL query string.
    category = request.args.get("category")

    # The input is not validated or sanitized. It is concatenated directly into a SQL query.
    # This is the classic setup for SQL Injection.
    db = sqlite3.connect("database.db")
    cursor = db.cursor()
    query = f"SELECT id, name, price FROM products WHERE category = '{category}'"

    # Attacker's request: /api/products?category=' OR 1=1 --
    # The resulting query becomes: "SELECT ... FROM products WHERE category = '' OR 1=1 --'"
    # This will return ALL products in the database, bypassing the filter.
    cursor.execute(query)
    products = cursor.fetchall()
    return {"products": products}
```

### GOOD Code Example

```python
# SECURE: All input is validated on the server against a strict allowlist.
from flask import request
import sqlite3

# Define a strict allowlist of known-good values for the 'category' parameter.
ALLOWED_CATEGORIES = {"electronics", "books", "clothing", "homegoods"}

@app.route("/api/products/safe")
def search_products_safe():
    category = request.args.get("category")

    # 1. VALIDATE EXISTENCE: Check if the parameter was provided.
    if not category:
        return {"error": "Category parameter is required."}, 400

    # 2. VALIDATE AGAINST ALLOWLIST: Check if the input is one of the expected values.
    #    This is the strongest form of input validation.
    if category not in ALLOWED_CATEGORIES:
        return {"error": "Invalid category specified."}, 400

    # 3. USE PARAMETERIZED QUERIES: Even after validation, use safe database APIs
    #    to prevent any possibility of injection.
    db = sqlite3.connect("database.db")
    cursor = db.cursor()
    # The '?' placeholder ensures the input is treated as data, not code.
    query = "SELECT id, name, price FROM products WHERE category = ?"
    cursor.execute(query, (category,))
    products = cursor.fetchall()
    return {"products": products}
```

## Detection

- **Trace user input:** For every piece of data that comes from an HTTP request (URL parameters, POST body, headers, cookies), follow it through the code and verify that it is validated before it is used.
- **Look for client-side-only validation:** Check if `required` attributes in HTML or JavaScript validation functions are the only form of validation. If there's no equivalent check on the server, it's vulnerable.
- **Search for missing checks:** Look for code that handles input without checking its type, length, format, or range.

## Prevention

The "Validate, then Act" principle must be applied to all incoming data.

- [ ] **Validate everything on the server:** Client-side validation is for user experience only; it provides no security.
- [ ] **Be strict with what you accept (Allowlist):** It is always better to have a list of known-good inputs (an allowlist) than to try to block known-bad inputs (a blocklist).
- [ ] **Implement a multi-layered validation strategy:**
  - **Type:** Ensure the data is the expected type (e.g., a number, not a string).
  - **Length:** Enforce minimum and maximum lengths to prevent buffer overflows and denial-of-service.
  - **Format:** For data like email addresses or phone numbers, check that it conforms to the expected format (e.g., using a regular expression).
  - **Range:** For numerical data, check that it falls within an expected range.
- [ ] **Use a schema validation library:** For complex inputs like JSON or XML, use a library (like Pydantic, JSON Schema, or Marshmallow) to define and enforce the structure of the incoming data.

## Related Security Patterns & Anti-Patterns

Missing input validation is the root cause of most major vulnerability classes.

- [SQL Injection Anti-Pattern](../sql-injection/)
- [Cross-Site Scripting (XSS) Anti-Pattern](../xss/)
- [Command Injection Anti-Pattern](../command-injection/)
- [Path Traversal Anti-Pattern](../path-traversal/)

## References

- [OWASP Top 10 A05:2025 - Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)
- [OWASP GenAI LLM05:2025 - Improper Output Handling](https://genai.owasp.org/llmrisk/llm05-improper-output-handling/)
- [OWASP API Security API8:2023 - Security Misconfiguration](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CAPEC-153: Input Data Manipulation](https://capec.mitre.org/data/definitions/153.html)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
