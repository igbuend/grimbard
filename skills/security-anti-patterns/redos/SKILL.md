---
name: "redos-anti-pattern"
description: "Security anti-pattern for Regular Expression Denial of Service (CWE-1333). Use when generating or reviewing code that uses regex for input validation, parsing, or pattern matching. Detects catastrophic backtracking patterns with nested quantifiers."
---

# ReDoS (Regular Expression Denial of Service) Anti-Pattern

**Severity:** High

## Summary
A Regular Expression Denial of Service (ReDoS) is a vulnerability that occurs when a poorly written regular expression takes an extremely long time to evaluate a maliciously crafted input. This can cause the application or server to hang, consuming 100% of a CPU core for seconds or even minutes from a single request. The vulnerability is caused by a phenomenon called "catastrophic backtracking," which is common in regex patterns that have nested quantifiers (e.g., `(a+)+`) or overlapping alternations.

## The Anti-Pattern
The anti-pattern is using a regex with exponential-time complexity to validate user-provided input. A small increase in the length of the attacker's input can lead to an exponential increase in the regex engine's computation time.

### BAD Code Example
```javascript
// VULNERABLE: A regex with nested quantifiers used for validation.

// This regex tries to validate a string composed of 'a's followed by a 'b'.
// The `(a+)+` part is the "evil" pattern. It creates catastrophic backtracking.
const VULNERABLE_REGEX = /^(a+)+b$/;

function validateString(input) {
    console.time('Regex Execution');
    const result = VULNERABLE_REGEX.test(input);
    console.timeEnd('Regex Execution');
    return result;
}

// For a normal string, it's fast.
// validateString("aaab"); // -> true, executes in < 1ms

// But an attacker provides a string that *almost* matches.
const malicious_input = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaab"; // 30 'a's and a 'b'

// With this input, the regex engine gets stuck.
// The `(a+)+` part can match the string of 'a's in an exponential number of ways.
// For example, "aaa" can be matched as (a)(a)(a), (aa)(a), (a)(aa), or (aaa).
// The engine must try every single combination before it can confirm the match.
// For 30 'a's, this results in over 1 billion backtracking steps, freezing the process.
validateString(malicious_input); // This will hang for a very long time.
```

### GOOD Code Example
```javascript
// SECURE: Rewrite the regex to be linear-time, or add other controls.

// Option 1 (Best): Fix the regex by removing the nested quantifier.
// This version is functionally identical but has linear-time complexity.
const SAFE_REGEX = /^a+b$/;

function validateStringSafe(input) {
    console.time('Regex Execution');
    // This will now fail almost instantly for the malicious input.
    const result = SAFE_REGEX.test(input);
    console.timeEnd('Regex Execution');
    return result;
}

// Option 2: Add an input length limit as a defense-in-depth measure.
const MAX_LENGTH = 50;
function validateStringWithLimit(input) {
    if (input.length > MAX_LENGTH) {
        throw new Error("Input exceeds maximum length.");
    }
    // Still better to use the safe regex, but this provides a fallback.
    return VULNERABLE_REGEX.test(input);
}

// Option 3: Use a modern regex engine (like Google's RE2) that is designed
// to avoid catastrophic backtracking and guarantee linear-time execution.
```

## Detection
- **Scan for "evil" regex patterns:** The most common red flags are nested quantifiers. Look for patterns like:
    - `(a+)+`
    - `(a*)*`
    - `(a|a)+`
    - `(a?)*`
- **Look for alternations with overlapping patterns:** `(a|b)*` is safe, but `(a|ab)*` is not, because `ab` can be matched in two different ways.
- **Use static analysis tools:** There are many linters and security scanners that are specifically designed to detect vulnerable regular expressions in your code (e.g., `safe-regex` for Node.js).
- **Test with "almost matching" strings:** To test a regex, create a long string that matches the repeating part of the pattern but fails at the very end. If the execution time increases dramatically with the length of the string, it is likely vulnerable.

## Prevention
- [ ] **Avoid nested quantifiers:** This is the most important rule. A pattern like `(a+)+` can almost always be rewritten more safely as `a+`.
- [ ] **Be wary of alternations:** Ensure that alternations within a repeated group do not overlap (e.g., use `(a|b)` not `(a|ab)`).
- [ ] **Limit input length:** Before applying a complex regex, always validate the length of the input string. This provides an effective, though crude, defense against ReDoS by capping the potential execution time.
- [ ] **Use a timeout:** Some languages and libraries allow you to execute a regex match with a timeout. This can prevent a ReDoS attack from freezing a process indefinitely, although it doesn't fix the underlying vulnerable regex.
- [ ] **Use a ReDoS-safe regex engine:** Consider using an alternative regex engine like Google's RE2, which guarantees linear-time performance and is immune to catastrophic backtracking.

## Related Security Patterns & Anti-Patterns
- [Missing Input Validation Anti-Pattern](../missing-input-validation/): Failing to limit input length is a form of missing validation that makes ReDoS attacks possible.
- [Denial of Service (DoS):](../#) ReDoS is a specific type of application-layer DoS attack.

## References
- [OWASP Top 10 A06:2025 - Insecure Design](https://owasp.org/Top10/2025/A06_2025-Insecure_Design/)
- [OWASP GenAI LLM10:2025 - Unbounded Consumption](https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/)
- [OWASP API Security API4:2023 - Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)
- [OWASP ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
- [CWE-1333: Inefficient Regular Expression](https://cwe.mitre.org/data/definitions/1333.html)
- [CAPEC-492: Regular Expression Exponential Blowup](https://capec.mitre.org/data/definitions/492.html)
- [safe-regex npm package](https://www.npmjs.com/package/safe-regex)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
