---
name: mutation-xss-anti-pattern
description: Security anti-pattern for mutation XSS (mXSS) vulnerabilities (CWE-79 variant). Use when generating or reviewing code that sanitizes HTML content, handles user-provided markup, or processes rich text. Detects sanitizer bypass through browser parsing mutations.
---

# Mutation XSS (mXSS) Anti-Pattern

**Severity:** High

## Risk

Mutation XSS occurs when browsers "fix" malformed HTML during parsing, resulting in executable content that bypasses sanitization. The sanitizer processes one DOM tree, but the browser creates a different one. This leads to:

- Bypassing HTML sanitizers
- XSS through seemingly safe content
- Difficult to detect and test
- Affects even well-tested sanitizers

## BAD Pattern: Sanitizer Bypass Through Mutations

```pseudocode
// VULNERABLE: Browser mutations can bypass sanitization

// How mXSS works:
// 1. Sanitizer processes malformed HTML
// 2. Browser "fixes" the HTML during parsing
// 3. Fixed HTML contains executable content

// Example: Backtick mutation
input_html = "<img src=x onerror=`alert(1)`>"
// Some sanitizers don't escape backticks
// Browser may convert backticks to quotes in certain contexts

// Example: Namespace confusion
input_html = "<math><annotation-xml><foreignObject><script>alert(1)</script>"
// SVG/MathML namespaces have different parsing rules
// Sanitizer might miss the nested script

// Example: Table element mutations
input_html = "<table><form><input name='x'></form></table>"
// Browser moves <form> outside <table> during parsing
// Can result in unexpected DOM structure

FUNCTION render_user_content_unsafe(html):
    // Simple sanitizer may miss mutation vectors
    cleaned = simple_sanitizer.clean(html)
    element.innerHTML = cleaned
    // Browser parses and "fixes" the HTML
    // Mutation creates executable content
END FUNCTION
```

## BAD Pattern: Namespace Confusion

```pseudocode
// VULNERABLE: SVG/MathML namespace allows script execution

input_html = """
<svg>
    <foreignObject>
        <body xmlns="http://www.w3.org/1999/xhtml">
            <script>alert(document.domain)</script>
        </body>
    </foreignObject>
</svg>
"""

// Sanitizer processes as SVG (different rules)
// Browser switches namespace context
// Script executes in HTML namespace
```

## GOOD Pattern: Battle-Tested Sanitizer with mXSS Protection

```pseudocode
// SECURE: Use DOMPurify with mXSS protection

FUNCTION sanitize_html(html):
    RETURN DOMPurify.sanitize(html, {
        // DOMPurify has mXSS protection built-in
        USE_PROFILES: {html: TRUE},
        // Optionally restrict further
        FORBID_TAGS: ["style", "math", "svg"],
        FORBID_ATTR: ["style"]
    })
END FUNCTION

// BETTER: Avoid HTML sanitization when possible
FUNCTION render_user_content_safe(content):
    // If you only need formatted text, use markdown
    markdown_html = markdown_to_html(content)  // Controlled conversion
    RETURN DOMPurify.sanitize(markdown_html)
END FUNCTION
```

## GOOD Pattern: Restrict Dangerous Elements

```pseudocode
// SECURE: Strict allowlist approach

FUNCTION sanitize_strict(html):
    RETURN DOMPurify.sanitize(html, {
        ALLOWED_TAGS: ["p", "b", "i", "em", "strong", "a", "br"],
        ALLOWED_ATTR: ["href"],
        ALLOW_DATA_ATTR: FALSE,

        // Block namespace-switching elements
        FORBID_TAGS: ["svg", "math", "foreignObject", "annotation-xml"],

        // Use safe parsing
        FORCE_BODY: TRUE,
        SANITIZE_DOM: TRUE
    })
END FUNCTION
```

## Common mXSS Vectors

| Vector | Example | Mutation |
|--------|---------|----------|
| Backticks | `onerror=\`alert(1)\`` | May become quotes |
| Namespace | `<svg><foreignObject>` | Script context switch |
| Table nesting | `<table><form>` | Form moved outside |
| Comments | `<!--<script>-->` | Comment parsing varies |
| Processing instructions | `<?xml?>` | Parser confusion |

## Detection

Test sanitizer output with:
- Malformed nesting (`<a><table><a>`)
- Namespace elements (`<svg>`, `<math>`, `<foreignObject>`)
- Backticks and other unusual quote characters
- Processing instruction-like content (`<?xml>`)
- Deeply nested structures
- Mixed namespace content

## Prevention Checklist

- [ ] Use DOMPurify or similarly battle-tested sanitizer
- [ ] Keep sanitizer library up to date (mXSS patches frequent)
- [ ] Forbid SVG, MathML, and foreignObject unless needed
- [ ] Consider markdown instead of HTML for user content
- [ ] Use CSP as defense in depth
- [ ] Test with known mXSS payloads
- [ ] Set FORCE_BODY: TRUE in DOMPurify

## Related Patterns

- [xss](../xss/) - Base XSS pattern
- [dom-clobbering](../dom-clobbering/) - Related DOM manipulation attack
- [encoding-bypass](../encoding-bypass/) - Another sanitizer bypass technique

## References

- [OWASP Top 10 A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)
- [CAPEC-86: XSS Through HTTP Headers](https://capec.mitre.org/data/definitions/86.html)
- [DOMPurify](https://github.com/cure53/DOMPurify)
- [Mutation XSS Research](https://cure53.de/fp170.pdf)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
