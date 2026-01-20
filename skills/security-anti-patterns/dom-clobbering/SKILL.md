---
name: dom-clobbering-anti-pattern
description: Security anti-pattern for DOM clobbering vulnerabilities (CWE-79 variant). Use when generating or reviewing code that accesses DOM elements by ID, uses global variables, or relies on document properties. Detects HTML injection that overwrites JavaScript globals.
---

# DOM Clobbering Anti-Pattern

**Severity:** Medium

## Risk

DOM clobbering occurs when HTML elements with `id` or `name` attributes create global variables that override JavaScript globals or DOM properties. Even sanitized HTML can clobber the DOM. This leads to:

- Overwriting security-critical JavaScript functions
- Hijacking navigation and form submissions
- Bypassing client-side security checks
- Enabling further XSS attacks

## How DOM Clobbering Works

```pseudocode
// HTML elements with id/name create global variables

// This HTML:
<img id="alert">

// Creates: window.alert === <img> element
// Now: alert(1) throws error instead of showing alert

// This HTML:
<form id="document"><input name="cookie" value="fake"></form>

// Can interfere with: document.cookie
// The form element may shadow the real document object
```

## BAD Pattern: Global Lookups for Security Operations

```pseudocode
// VULNERABLE: Using global lookups for security-critical operations

FUNCTION get_config_value(key):
    // Attacker injects: <img id="apiKey" src="x" data-value="evil">
    RETURN window[key]  // Returns the img element, not config value
END FUNCTION

FUNCTION redirect_to_profile(user_id):
    // Attacker injects: <a id="profileUrl" href="javascript:alert(1)">
    url = document.getElementById("profileUrl")
    location = url.href  // XSS!
END FUNCTION

FUNCTION check_admin_status():
    // Attacker injects: <img id="isAdmin" src="x">
    IF window.isAdmin:
        show_admin_panel()  // Element is truthy, grants access
    END IF
END FUNCTION
```

## BAD Pattern: Chained Property Access

```pseudocode
// VULNERABLE: Nested clobbering through forms

// Attacker injects:
<form id="config">
    <input name="apiUrl" value="https://evil.com">
    <input name="debug" value="true">
</form>

// Code expects config object:
FUNCTION init_app():
    api_url = config.apiUrl  // Gets input element or its value
    debug_mode = config.debug  // Attacker controls this
END FUNCTION
```

## GOOD Pattern: Namespaced Configuration

```pseudocode
// SECURE: Use namespaced config object

CONSTANT APP_CONFIG = {
    apiUrl: "https://api.example.com",
    debug: FALSE
}

FUNCTION get_config_value(key):
    // DON'T: return window[key]
    // DON'T: return document.getElementById(key).value

    // DO: Use a namespaced config object
    RETURN APP_CONFIG[key]
END FUNCTION
```

## GOOD Pattern: Prefixed Element IDs

```pseudocode
// SECURE: Use unique prefixes for security-critical IDs

FUNCTION get_element_by_id_safe(id):
    // Prefix with app-specific namespace
    RETURN document.getElementById("app__" + id)
END FUNCTION

FUNCTION render_user_content(html):
    // Sanitize AND prefix any IDs
    sanitized = DOMPurify.sanitize(html, {
        SANITIZE_DOM: TRUE,
        // Custom hook to prefix all IDs
        hooks: {
            afterSanitizeAttributes: FUNCTION(node):
                IF node.hasAttribute("id"):
                    node.id = "user_content__" + node.id
                END IF
            END FUNCTION
        }
    })
    RETURN sanitized
END FUNCTION
```

## GOOD Pattern: Type Validation After DOM Queries

```pseudocode
// SECURE: Validate types after DOM queries

FUNCTION get_form_element(id):
    element = document.getElementById(id)

    IF element IS NULL:
        THROW Error("Element not found")
    END IF

    IF NOT (element instanceof HTMLFormElement):
        THROW Error("Expected form element")
    END IF

    RETURN element
END FUNCTION

FUNCTION get_input_value(id):
    element = document.getElementById(id)

    IF NOT (element instanceof HTMLInputElement):
        THROW Error("Expected input element")
    END IF

    RETURN element.value
END FUNCTION
```

## Dangerous Global Names

| Name | Risk |
|------|------|
| `alert`, `confirm`, `prompt` | Disable dialogs |
| `document`, `window` | Shadow core objects |
| `location`, `top`, `self` | Control navigation |
| `name`, `status` | Common property names |
| `cookie`, `domain` | Security-sensitive properties |
| Form names matching API objects | Shadow application config |

## Detection

Test with elements having IDs matching:
- JavaScript globals (`alert`, `name`, `location`)
- Object properties (`cookie`, `domain`)
- Application-specific config names
- Nested forms with chained name/id attributes
- Security-critical element IDs in your application

## Prevention Checklist

- [ ] Never use global lookups (`window[key]`) for security operations
- [ ] Use namespaced configuration objects
- [ ] Prefix user-content element IDs with unique namespace
- [ ] Validate element types after DOM queries
- [ ] Use Object.freeze() on security-critical configs
- [ ] Enable DOMPurify's SANITIZE_DOM option
- [ ] Avoid relying on element IDs for security logic

## Related Patterns

- [xss](../xss/) - Base XSS pattern
- [mutation-xss](../mutation-xss/) - Related sanitizer bypass
- [missing-input-validation](../missing-input-validation/) - Type validation

## References

- [OWASP Top 10 A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)
- [CAPEC-588: DOM-Based XSS](https://capec.mitre.org/data/definitions/588.html)
- [PortSwigger DOM Clobbering](https://portswigger.net/web-security/dom-based/dom-clobbering)
- [DOM Clobbering Research](https://research.securitum.com/xss-in-chrome-extensions-with-dom-clobbering/)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
