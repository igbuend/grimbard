---
name: "mutation-xss-anti-pattern"
description: "Security anti-pattern for mutation XSS (mXSS) vulnerabilities (CWE-79 variant). Use when generating or reviewing code that sanitizes HTML content, handles user-provided markup, or processes rich text. Detects sanitizer bypass through browser parsing mutations."
---

# Mutation XSS (mXSS) Anti-Pattern

**Severity:** High

## Summary

Mutation XSS (mXSS) is a sophisticated type of Cross-Site Scripting that bypasses HTML sanitizers. The vulnerability occurs because of inconsistencies in how a sanitizer library and a web browser parse malformed HTML. An attacker provides a string of HTML that appears safe to the sanitizer. However, when that "sanitized" HTML is inserted into the DOM, the browser's own parsing engine "corrects" the malformed code in a way that creates an executable script. The sanitizer sees one DOM, but the browser creates a different, malicious one.

## The Anti-Pattern

The anti-pattern is relying on an HTML sanitizer without accounting for the browser's aggressive and sometimes unpredictable HTML parsing behavior. The sanitizer is defeated because the final DOM tree created by the browser is different from what the sanitizer checked.

### BAD Code Example

```javascript
// VULNERABLE: A simple sanitizer that is unaware of browser mutations.

function simpleSanitize(html) {
    // This sanitizer is naive. It looks for `<script>` tags and removes them.
    // It doesn't understand the complex ways browsers parse broken HTML.
    return html.replace(/<script.*?>.*?<\/script>/gi, '');
}

function renderComment(commentHtml) {
    const sanitizedHtml = simpleSanitize(commentHtml);
    // The sanitized HTML is inserted into the page.
    document.getElementById('comments').innerHTML = sanitizedHtml;
}

// Attacker's payload:
// const payload = '<noscript><p title="</noscript><img src=x onerror=alert(1)>">';

// 1. The `simpleSanitize` function sees no `<script>` tags and does nothing.
//    The `sanitizedHtml` is identical to the payload.

// 2. The browser receives this string:
//    '<noscript><p title="</noscript><img src=x onerror=alert(1)>">'

// 3. The browser's HTML parser tries to fix this broken structure:
//    - It sees `<noscript>`.
//    - It sees `<p title="`.
//    - It sees `</noscript>`, which it treats as malformed text inside the title attribute.
//    - Crucially, it continues parsing and sees `<img src=x onerror=alert(1)>`.
//    - It creates an `<img>` element with an `onerror` attribute.

// 4. The `onerror` event fires, executing the attacker's script. The sanitizer has been completely bypassed.
renderComment(payload);
```

### GOOD Code Example

```javascript
// SECURE: Use a mature, well-maintained, and mutation-aware HTML sanitizer like DOMPurify.

function renderCommentSafe(commentHtml) {
    // DOMPurify is specifically designed to understand and defeat mXSS.
    // It works by parsing the HTML into a DOM tree within a sandbox, removing anything
    // dangerous, and then serializing it back into a clean HTML string.
    // It is aware of the many weird parsing quirks across different browsers.
    const sanitizedHtml = DOMPurify.sanitize(commentHtml);

    document.getElementById('comments').innerHTML = sanitizedHtml;
}

// When DOMPurify sanitizes the same payload, it correctly identifies the broken
// HTML and strips out the malicious `onerror` attribute, neutralizing the attack.
const payload = '<noscript><p title="</noscript><img src=x onerror=alert(1)>">';
renderCommentSafe(payload);

// It's also good practice to combine this with a strong Content Security Policy (CSP)
// as a defense-in-depth measure.
```

## Detection

- **mXSS is extremely difficult to detect manually.** It relies on deep knowledge of browser-specific parsing edge cases.
- **Review Sanitizer Choice:** Check if the application uses a known-vulnerable or homegrown HTML sanitizer. If it's not a library like DOMPurify that is actively maintained to fight mXSS, it is likely vulnerable.
- **Use mXSS-specific payloads:** Test the application's sanitizer with known mXSS payloads from security research (e.g., from the Cure53 research paper).

## Prevention

- [ ] **Use a battle-tested, mXSS-aware sanitizer library.** The current industry standard is **DOMPurify**. Do not attempt to write your own sanitizer.
- [ ] **Keep your sanitizer library up to date.** New mXSS vectors are discovered periodically, and libraries are updated with new defenses.
- [ ] **Configure the sanitizer for maximum safety.** Forbid dangerous tags like `<style>`, `<svg>`, and `<math>` unless they are absolutely necessary.
- [ ] **Implement a strong Content Security Policy (CSP)** as a second layer of defense. A strict CSP can block inline event handlers (`onerror`) and untrusted scripts, preventing the mXSS payload from executing even if the sanitizer fails.
- [ ] **Avoid HTML sanitization if possible.** If you only need simple formatting like bold or italics, consider using Markdown and a safe Markdown-to-HTML converter instead of allowing raw HTML input.

## Related Security Patterns & Anti-Patterns

- [Cross-Site Scripting (XSS) Anti-Pattern](../xss/): mXSS is a specific and advanced technique for achieving XSS.
- [DOM Clobbering Anti-Pattern](../dom-clobbering/): Another client-side attack that abuses the browser's DOM manipulation behavior.
- [Encoding Bypass Anti-Pattern](../encoding-bypass/): A different technique for bypassing input filters and sanitizers.

## References

- [OWASP Top 10 A05:2025 - Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)
- [OWASP GenAI LLM09:2025 - Misinformation](https://genai.owasp.org/llmrisk/llm09-misinformation/)
- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)
- [CAPEC-86: XSS Through HTTP Headers](https://capec.mitre.org/data/definitions/86.html)
- [DOMPurify](https://github.com/cure53/DOMPurify)
- [Mutation XSS Research (Cure53)](https://cure53.de/fp170.pdf)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
