---
name: "integer-overflow-anti-pattern"
description: "Security anti-pattern for integer overflow vulnerabilities (CWE-190). Use when generating or reviewing code that performs arithmetic on user-controlled values, handles sizes/quantities, or calculates prices/amounts. Detects overflow in validated inputs."
---

# Integer Overflow Anti-Pattern

**Severity:** High

## Summary

An integer overflow occurs when an arithmetic operation, such as addition or multiplication, results in a number that is too large to be stored in the available memory space for that data type. Instead of causing an error, the value often "wraps around," becoming a very small or negative number. This anti-pattern is particularly dangerous when user-controlled inputs, which may be individually valid, are combined in a calculation. Attackers can exploit this to bypass security checks, cause buffer overflows, or manipulate financial transactions.

## The Anti-Pattern

The anti-pattern is performing arithmetic operations on user-controlled inputs without first checking if the operation could exceed the maximum value for the integer type. Validation of the individual inputs is not sufficient.

### BAD Code Example

```c
// VULNERABLE: Individual values are checked, but their multiplication can overflow.
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

void process_purchase(uint32_t quantity, uint32_t price_per_item) {
    // Both inputs are validated and seem reasonable on their own.
    if (quantity > 1000) {
        printf("Error: Quantity too high.\n");
        return;
    }
    if (price_per_item > 100000) {
        printf("Error: Price per item too high.\n");
        return;
    }

    // Attacker sets `quantity = 50000` and `price_per_item = 100000`.
    // Both might pass initial checks if those checks are weak.
    // The expected total is 5,000,000,000.
    // The maximum value for a 32-bit unsigned integer is 4,294,967,295.
    uint32_t total_cost = quantity * price_per_item; // OVERFLOW!

    // The `total_cost` wraps around to a small number (705,032,704 in this case).
    // The attacker is charged a fraction of the real price.
    printf("Charging customer: %u\n", total_cost);
    charge_customer(total_cost);
}
```

### GOOD Code Example

```c
// SECURE: Check for potential overflow before performing the multiplication.
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

void process_purchase_safe(uint32_t quantity, uint32_t price_per_item) {
    if (quantity > 1000) {
        printf("Error: Quantity too high.\n");
        return;
    }
    if (price_per_item > 100000) {
        printf("Error: Price per item too high.\n");
        return;
    }

    // Pre-condition check: before multiplying, verify if the result would exceed the maximum value.
    if (price_per_item > 0 && quantity > UINT32_MAX / price_per_item) {
        printf("Error: Potential overflow detected. Transaction cancelled.\n");
        return;
    }

    // The multiplication is now safe to perform.
    uint32_t total_cost = quantity * price_per_item;

    printf("Charging customer: %u\n", total_cost);
    charge_customer(total_cost);
}
```

## Detection

- **Review arithmetic operations:** Look for any code where two or more user-controlled numerical inputs are added, multiplied, or otherwise combined.
- **Check validation logic:** Ensure that validation doesn't just check the range of individual inputs but also considers the potential result of their combination.
- **Test with boundary values:** Use the maximum value for a given integer type (e.g., `2,147,483,647` for a 32-bit signed integer) in your tests to see how the application handles it.
- **Use static analysis tools:** Many static code analysis (SAST) tools can detect potential integer overflow conditions.

## Prevention

- [ ] **Check before you calculate:** Before performing an arithmetic operation, check if it will result in an overflow. For multiplication (`a * b`), the check is `if (a > MAX_INT / b)`. For addition (`a + b`), it's `if (a > MAX_INT - b)`.
- [ ] **Use a larger data type:** If you expect large numbers, use a 64-bit integer (`long long` in C, `long` in Java) instead of a 32-bit one.
- [ ] **Use arbitrary-precision libraries:** For financial calculations where precision is critical, use a library that handles numbers of arbitrary size (e.g., `BigDecimal` in Java, `decimal` in Python).
- [ ] **Use compiler-level protections:** Some modern compilers provide flags (like `-ftrapv` in GCC/Clang) that can detect and abort on signed integer overflows.

## Related Security Patterns & Anti-Patterns

- [Missing Input Validation Anti-Pattern](../missing-input-validation/): While input validation is necessary, it is not sufficient on its own to prevent integer overflows.
- [Type Confusion Anti-Pattern](../type-confusion/): Incorrect assumptions about data types can lead to a variety of numeric vulnerabilities, including overflows.

## References

- [OWASP Top 10 A05:2025 - Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)
- [OWASP GenAI LLM10:2025 - Unbounded Consumption](https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/)
- [CWE-190: Integer Overflow](https://cwe.mitre.org/data/definitions/190.html)
- [CAPEC-190: Forced Integer Overflow](https://capec.mitre.org/data/definitions/190.html)
- [CERT Secure Coding - Integer Security](https://wiki.sei.cmu.edu/confluence/display/c/INT32-C.+Ensure+that+operations+on+signed+integers+do+not+result+in+overflow)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
