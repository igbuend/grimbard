---
name: integer-overflow-anti-pattern
description: Security anti-pattern for integer overflow vulnerabilities (CWE-190). Use when generating or reviewing code that performs arithmetic on user-controlled values, handles sizes/quantities, or calculates prices/amounts. Detects overflow in validated inputs.
---

# Integer Overflow Anti-Pattern

**Severity:** High

## Risk

Integer overflow occurs when arithmetic operations exceed the maximum (or minimum) value for an integer type, causing wraparound. Individual values may pass validation, but their combination overflows. This leads to:

- Financial manipulation (paying $0 for large orders)
- Buffer allocation errors
- Access control bypass
- Denial of service

## BAD Pattern: Validation Passes, Computation Overflows

```pseudocode
// VULNERABLE: Individual values valid, multiplication overflows

FUNCTION vulnerable_purchase(quantity, price):
    // Validate individual ranges - both pass!
    IF quantity < 0 OR quantity > 1000000:
        RETURN error("Invalid quantity")
    END IF
    IF price < 0 OR price > 1000000:
        RETURN error("Invalid price")
    END IF

    // Both pass validation, but multiplication overflows!
    // quantity = 999999, price = 999999
    // total = 999998000001 (exceeds 32-bit signed integer max: 2147483647)
    total = quantity * price  // OVERFLOW!

    // In 32-bit signed: wraps to negative or small number
    // Customer charged wrong amount
    charge_customer(total)
END FUNCTION
```

## BAD Pattern: Size Calculation Overflow

```pseudocode
// VULNERABLE: Buffer size calculation overflows

FUNCTION vulnerable_allocate(width, height, bytes_per_pixel):
    // Each value looks reasonable
    IF width > 10000 OR height > 10000:
        RETURN error("Image too large")
    END IF

    // But multiplication can overflow
    // width=5000, height=5000, bytes_per_pixel=4
    // size = 5000 * 5000 * 4 = 100,000,000 (OK in 32-bit)
    // width=50000, height=50000, bytes_per_pixel=4
    // size = 50000 * 50000 * 4 = 10,000,000,000 (overflows 32-bit)
    size = width * height * bytes_per_pixel

    // Small buffer allocated due to overflow
    buffer = allocate(size)

    // Write to buffer causes heap overflow
    process_image(buffer, width, height)
END FUNCTION
```

## BAD Pattern: Array Index Calculation

```pseudocode
// VULNERABLE: Index calculation wraps around

FUNCTION vulnerable_array_access(base_index, offset):
    // Both values validated individually
    IF base_index < 0 OR base_index > MAX_INDEX:
        RETURN error("Invalid index")
    END IF
    IF offset < 0 OR offset > MAX_OFFSET:
        RETURN error("Invalid offset")
    END IF

    // Addition can overflow
    final_index = base_index + offset  // Might wrap to small/negative value

    // Out-of-bounds access
    RETURN array[final_index]
END FUNCTION
```

## GOOD Pattern: Check Before Computation

```pseudocode
// SECURE: Check for overflow before computing

FUNCTION secure_purchase(quantity, price):
    // Validate individual ranges
    IF NOT is_valid_integer(quantity, 1, 1000):
        RETURN error("Invalid quantity")
    END IF
    IF NOT is_valid_integer(price, 1, 10000000):  // in cents
        RETURN error("Invalid price")
    END IF

    // Check multiplication won't overflow BEFORE computing
    MAX_SAFE_TOTAL = 2147483647  // 32-bit signed max

    IF quantity > MAX_SAFE_TOTAL / price:
        RETURN error("Order total too large")
    END IF

    // Now safe to compute
    total = quantity * price

    // Additional business validation
    IF total > MAX_ALLOWED_TRANSACTION:
        RETURN error("Transaction exceeds limit")
    END IF

    charge_customer(total)
END FUNCTION
```

## GOOD Pattern: Use Arbitrary Precision

```pseudocode
// SECURE: Use arbitrary precision for money

FUNCTION secure_purchase_decimal(quantity, price):
    // Convert to arbitrary precision decimal
    quantity_decimal = Decimal(quantity)
    price_decimal = Decimal(price)

    // No overflow possible with arbitrary precision
    total = quantity_decimal * price_decimal

    IF total > Decimal(MAX_ALLOWED_TRANSACTION):
        RETURN error("Transaction exceeds limit")
    END IF

    charge_customer(total)
END FUNCTION
```

## GOOD Pattern: Safe Arithmetic Functions

```pseudocode
// SECURE: Use safe arithmetic functions that check overflow

FUNCTION safe_multiply(a, b):
    // Check for overflow before multiplication
    IF a > 0 AND b > 0 AND a > MAX_INT / b:
        THROW OverflowError("Multiplication would overflow")
    END IF
    IF a < 0 AND b < 0 AND a < MAX_INT / b:
        THROW OverflowError("Multiplication would overflow")
    END IF
    IF a > 0 AND b < 0 AND b < MIN_INT / a:
        THROW OverflowError("Multiplication would overflow")
    END IF
    IF a < 0 AND b > 0 AND a < MIN_INT / b:
        THROW OverflowError("Multiplication would overflow")
    END IF

    RETURN a * b
END FUNCTION

FUNCTION safe_add(a, b):
    IF b > 0 AND a > MAX_INT - b:
        THROW OverflowError("Addition would overflow")
    END IF
    IF b < 0 AND a < MIN_INT - b:
        THROW OverflowError("Addition would underflow")
    END IF

    RETURN a + b
END FUNCTION
```

## Integer Limits by Type

| Type | Min | Max |
|------|-----|-----|
| int8 | -128 | 127 |
| uint8 | 0 | 255 |
| int16 | -32,768 | 32,767 |
| uint16 | 0 | 65,535 |
| int32 | -2,147,483,648 | 2,147,483,647 |
| uint32 | 0 | 4,294,967,295 |
| int64 | -9.2e18 | 9.2e18 |

## Detection

- Look for multiplication/addition of user-controlled values
- Check if overflow is considered in validation
- Review size/length calculations
- Test with MAX_INT, MAX_INT-1, boundary values
- Test combinations that multiply to overflow

## Prevention Checklist

- [ ] Check for potential overflow BEFORE arithmetic operations
- [ ] Use safe arithmetic functions that detect overflow
- [ ] Consider arbitrary precision for financial calculations
- [ ] Set business limits lower than technical limits
- [ ] Use appropriate integer sizes (64-bit for large values)
- [ ] Test with boundary values and overflow-inducing combinations
- [ ] Be aware of signed vs unsigned wraparound differences

## Related Patterns

- [missing-input-validation](../missing-input-validation/) - Validation alone isn't enough
- [type-confusion](../type-confusion/) - Related numeric issues

## References

- [OWASP Top 10 A05:2025 - Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)
- [CWE-190: Integer Overflow](https://cwe.mitre.org/data/definitions/190.html)
- [CAPEC-190: Forced Integer Overflow](https://capec.mitre.org/data/definitions/190.html)
- [CERT Secure Coding - Integer Security](https://wiki.sei.cmu.edu/confluence/display/c/INT32-C.+Ensure+that+operations+on+signed+integers+do+not+result+in+overflow)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
