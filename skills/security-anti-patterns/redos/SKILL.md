---
name: redos-anti-pattern
description: Security anti-pattern for Regular Expression Denial of Service (CWE-1333). Use when generating or reviewing code that uses regex for input validation, parsing, or pattern matching. Detects catastrophic backtracking patterns with nested quantifiers.
---

# ReDoS (Regular Expression DoS) Anti-Pattern

**Severity:** High

## Risk

ReDoS occurs when regex patterns with nested quantifiers or overlapping alternatives cause exponential backtracking. A single malicious input can consume 100% CPU for minutes. This leads to:

- Denial of service with single request
- Server/application hang
- Resource exhaustion
- No rate limiting defense (one request is enough)

## BAD Pattern: Nested Quantifiers

```pseudocode
// VULNERABLE: Nested quantifiers cause exponential backtracking

// Email validation with ReDoS vulnerability
VULNERABLE_EMAIL = "^([a-zA-Z0-9]+)*@[a-zA-Z0-9]+\.[a-zA-Z]+$"

// Attack input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
// The regex engine backtracks exponentially trying all combinations
// 25 'a's followed by '!' = 33 million+ combinations to try
// 30 'a's = 1 billion+ combinations

// URL validation with ReDoS
VULNERABLE_URL = "^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$"

// Attack input: "http://example.com/" + "a" * 30 + "!"

// Naive duplicate word finder (common tutorial example)
DUPLICATE_WORDS = "\b(\w+)\s+\1\b"
// Can hang on: "word word word word word word word word word word!"

FUNCTION validate_input_vulnerable(input, pattern):
    // This can hang for minutes or crash the server
    RETURN regex.match(pattern, input)
END FUNCTION
```

## BAD Pattern: Overlapping Alternatives

```pseudocode
// VULNERABLE: Overlapping character classes

// Pattern: (a|a)+
// Input: "aaaaaaaaaaaaaaaaaaaaX"
// Each 'a' can match via either alternative - exponential choices

// Pattern: (.*a){10}
// Input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX"
// .* can match varying amounts, causing massive backtracking

// Common vulnerable patterns:
VULNERABLE_PATTERNS = [
    "(a+)+",           // Nested quantifiers
    "(a*)*",           // Nested quantifiers
    "(a?)*",           // Nested quantifiers
    "(a|aa)+",         // Overlapping alternatives
    "(.*a){n}",        // Greedy with constraint
    "([a-zA-Z]+)*",    // Nested with character class
]
```

## GOOD Pattern: Linear-Time Regex

```pseudocode
// SECURE: Avoid nested quantifiers

// Instead of (a+)+ use:
SAFE_PATTERN = "a+"  // Single quantifier

// Instead of ([a-zA-Z0-9]+)* use:
SAFE_PATTERN = "[a-zA-Z0-9]*"  // Character class with single quantifier

// Safe email pattern (simplified):
SAFE_EMAIL = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

// Use possessive quantifiers where available (no backtracking):
// a++ instead of a+
// a*+ instead of a*
// (regex flavor dependent)
```

## GOOD Pattern: Input Length Limits

```pseudocode
// SECURE: Limit input length before regex

CONSTANT MAX_EMAIL_LENGTH = 254
CONSTANT MAX_URL_LENGTH = 2048

FUNCTION validate_email_safe(input):
    // Length check BEFORE regex
    IF length(input) > MAX_EMAIL_LENGTH:
        RETURN {valid: FALSE, error: "Email too long"}
    END IF

    // Now safe to apply regex (limited backtracking)
    pattern = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    RETURN regex.match(pattern, input)
END FUNCTION
```

## GOOD Pattern: Timeout on Regex

```pseudocode
// SECURE: Apply timeout to regex operations

FUNCTION validate_with_timeout(input, pattern, timeout_ms=100):
    TRY:
        result = regex.match_with_timeout(pattern, input, timeout_ms)
        RETURN {valid: result IS NOT NULL}
    CATCH TimeoutError:
        log.warning("Regex timeout - possible ReDoS attempt", {input_length: length(input)})
        RETURN {valid: FALSE, error: "Validation timeout"}
    END TRY
END FUNCTION
```

## Complexity Analysis

```pseudocode
// Pattern: (a+)+$
// Input: "aaaaaaaaaaaaaaaaaaaaaaaaX"
//
// For 25 'a's followed by 'X':
// - The engine tries every possible way to split the 'a's between groups
// - Time complexity: O(2^n) where n is input length
// - 25 chars = 33 million+ combinations to try
// - 30 chars = 1 billion+ combinations
// - 40 chars = 1 trillion+ combinations (server freeze)
```

## Red Flags in Regex Patterns

| Pattern | Risk | Alternative |
|---------|------|-------------|
| `(a+)+` | Exponential | `a+` |
| `(a*)*` | Exponential | `a*` |
| `(a\|aa)+` | Exponential | `a+` |
| `(.*a){n}` | Polynomial | Restructure logic |
| `([a-z]+)*` | Exponential | `[a-z]*` |

## Detection

- Search for nested quantifiers: `(pattern+)+`, `(pattern*)*`
- Look for overlapping alternatives in groups
- Check for `.*` followed by specific match requirements
- Test patterns with long inputs followed by non-matching character
- Use ReDoS detection tools (safe-regex, rxxr2)

## Prevention Checklist

- [ ] Avoid nested quantifiers (`(a+)+`, `(a*)*`, `(a?)*`)
- [ ] Limit input length before applying regex
- [ ] Use possessive quantifiers where available (`a++`)
- [ ] Set timeouts on regex operations
- [ ] Use ReDoS-safe regex libraries (RE2, rust regex)
- [ ] Test patterns with worst-case inputs
- [ ] Consider alternatives to regex for complex validation

## Related Patterns

- [missing-input-validation](../missing-input-validation/) - Length limits
- [missing-rate-limiting](../missing-rate-limiting/) - Defense in depth

## References

- [OWASP Top 10 A06:2025 - Insecure Design](https://owasp.org/Top10/2025/A06_2025-Insecure_Design/)
- [OWASP ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
- [CWE-1333: Inefficient Regular Expression](https://cwe.mitre.org/data/definitions/1333.html)
- [CAPEC-492: Regular Expression Exponential Blowup](https://capec.mitre.org/data/definitions/492.html)
- [safe-regex npm package](https://www.npmjs.com/package/safe-regex)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
