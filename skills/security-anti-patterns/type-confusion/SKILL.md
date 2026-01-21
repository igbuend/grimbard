---
name: "type-confusion-anti-pattern"
description: "Security anti-pattern for type confusion vulnerabilities (CWE-843). Use when generating or reviewing code in dynamic languages that compares values, processes JSON/user input, or uses loose equality. Detects weak typing exploits and type coercion attacks."
---

# Type Confusion Anti-Pattern

**Severity:** High

## Summary

Type confusion is a vulnerability that arises when a program treats a piece of data as one type (e.g., an integer) when it was intended to be another type (e.g., a string or an object). This can happen due to loose type comparisons, implicit type conversions (type coercion), or improper handling of varied input types. In weakly-typed languages like JavaScript or PHP, or when dealing with dynamic data structures like JSON, attackers can exploit type confusion to bypass security checks, manipulate logic, or even achieve code execution.

## The Anti-Pattern

The anti-pattern is relying on loose equality checks (`==` in JavaScript/PHP) or implicitly trusting the type of incoming data without explicit validation.

### BAD Code Example

```javascript
// VULNERABLE: Loose equality comparison in JavaScript.

// Imagine this check is used in an authentication or authorization context.
function checkAdminAccess(userId) {
    // Expected: userId is a string like "123".
    // Attacker's input: userId is a number 0.
    // In JavaScript, "0" == 0 evaluates to true due to type coercion.
    if (userId == 0) { // Loose equality check
        return true; // Grants admin access if userId is "0" or 0.
    }
    return false;
}

// Scenario 1: A user with `userId = "0"` (string) would gain admin access.
// Scenario 2: An attacker might be able to trick the application into passing
//             `userId = 0` (number) to this function, bypassing the check.

// Another common PHP example: "0e12345" == "0e56789" (both evaluate to 0 in scientific notation).
// If a user's hashed password starts with "0e", an attacker can provide another string whose
// hash also starts with "0e", bypassing authentication.
```

### GOOD Code Example

```javascript
// SECURE: Use strict equality comparison and explicit type validation.

// Option 1: Use strict equality (===) in JavaScript.
function checkAdminAccessSecure(userId) {
    // The `===` operator checks both value AND type.
    // So, "0" === 0 evaluates to false.
    if (userId === 0) {
        return true;
    }
    return false;
}

// Option 2: Explicitly validate the type of the input.
function processProductId(productId) {
    // Ensure `productId` is a string and matches expected format.
    if (typeof productId !== 'string' || !/^\d+$/.test(productId)) {
        throw new Error("Invalid product ID format.");
    }
    // Now you can safely use `productId` knowing its type and format.
    return parseInt(productId, 10);
}
```

## Detection

- **Code Review:**
  - **Loose equality operators:** Search for `==` in JavaScript or PHP code (prefer `===`).
  - **Implicit type conversions:** Look for contexts where a variable of one type might be implicitly converted to another, especially when performing comparisons or operations.
  - **Dynamic language features:** Be cautious with how user-provided data is used in contexts where the language might automatically infer or coerce types.
- **Input Validation:** Check if all incoming user input (JSON body, query parameters, form data) is explicitly validated for its expected data type *before* being processed.
- **Dynamic Queries:** Review code that constructs queries for NoSQL databases (like MongoDB) or other systems using user input. Attackers can often inject operators (`$gt`, `$ne`) by changing the input's type from a string to an object.

## Prevention

- [ ] **Use strict equality comparison:** In JavaScript, always use `===` instead of `==`. In PHP, use `===` for strict comparisons.
- [ ] **Validate all input types explicitly:** Before using any user-provided data, explicitly check and enforce its expected type. If you expect a string, ensure it's a string. If you expect an integer, convert it safely and validate its range.
- [ ] **Use schema validation:** For complex data structures (like JSON API requests), use a robust schema validation library (e.g., JSON Schema, Joi, Pydantic) that strictly enforces data types and formats.
- [ ] **Be careful with dynamic queries in NoSQL databases:** Avoid directly embedding user-controlled objects into NoSQL queries, as this can allow attackers to inject query operators. Sanitize or allowlist only specific field-value pairs.
- [ ] **Be aware of language-specific type juggling issues:** Understand how your chosen programming language handles type conversions and be vigilant in areas where this could be exploited.

## Related Security Patterns & Anti-Patterns

- [Missing Input Validation Anti-Pattern](../missing-input-validation/): Type validation is a fundamental part of comprehensive input validation.
- [Integer Overflow Anti-Pattern](../integer-overflow/): A specific type of numeric issue that can arise from unexpected type handling.
- [NoSQL Injection:](../#) Type confusion is a common vector for exploiting NoSQL databases.

## References

- [OWASP Top 10 A05:2025 - Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)
- [OWASP GenAI LLM05:2025 - Improper Output Handling](https://genai.owasp.org/llmrisk/llm05-improper-output-handling/)
- [OWASP API Security API8:2023 - Security Misconfiguration](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/)
- [CWE-843: Access of Resource Using Incompatible Type](https://cwe.mitre.org/data/definitions/843.html)
- [CAPEC-153: Input Data Manipulation](https://capec.mitre.org/data/definitions/153.html)
- [PHP Type Juggling (OWASP)](https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf)
- [NoSQL Injection Testing (OWASP)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
