# Security Review: OWASP Juice Shop

**Target:** OWASP Juice Shop v17.x  
**Review Date:** 2026-02-12  
**Methodology:** Grimbard automated security pattern analysis  
**Scope:** Server-side TypeScript — authentication, authorization, data handling, file uploads  
**Classification:** Example review (intentionally vulnerable application)

---

## Executive Summary

OWASP Juice Shop is an intentionally vulnerable web application used for security training. This review demonstrates the grimbard methodology by identifying the **most impactful** vulnerabilities across the server-side codebase using grimbard's security pattern and anti-pattern skills.

The review uncovered **16 findings** across the scoped files, ranging from critical SQL injection and remote code execution to high-severity cryptographic and authorization flaws. Every finding maps to a specific grimbard skill, demonstrating how pattern-based detection surfaces real vulnerabilities.

| Severity | Count |
|----------|-------|
| P0 (Critical) | 4 |
| P1 (High) | 6 |
| P2 (Medium) | 5 |
| P3 (Low) | 1 |

---

## P0 — Critical Findings

### 1. SQL Injection in Login

| Field | Value |
|-------|-------|
| **Severity** | P0 — Critical |
| **CWE** | CWE-89: SQL Injection |
| **Grimbard Skill** | `sql-injection-anti-pattern` |
| **Location** | `routes/login.ts:30` |

**Description:**  
User-supplied `email` is concatenated directly into a raw SQL query string:

```typescript
models.sequelize.query(
  `SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`,
  { model: UserModel, plain: true }
)
```

An attacker can bypass authentication entirely with a payload like `' OR 1=1--`.

**Impact:** Complete authentication bypass. Full database read/write via UNION-based or blind injection. Potential RCE via SQLite extensions.

**Remediation:** Use parameterized queries or Sequelize model methods (`UserModel.findOne({ where: { email, password } })`).

---

### 2. Hardcoded RSA Private Key

| Field | Value |
|-------|-------|
| **Severity** | P0 — Critical |
| **CWE** | CWE-798: Hardcoded Credentials |
| **Grimbard Skill** | `hardcoded-secrets-anti-pattern` |
| **Location** | `lib/insecurity.ts:21-23` |

**Description:**  
The JWT signing private key is embedded as a string literal in source code:

```typescript
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAKBgQDNwq...'
```

Anyone with source access (or who decompiles the deployed bundle) can forge arbitrary JWTs for any user, including admin.

**Impact:** Complete authentication bypass. Arbitrary user impersonation. Admin access.

**Remediation:** Load keys from environment variables or a secrets manager. Never commit private keys to source.

---

### 3. Remote Code Execution via B2B Order Processing

| Field | Value |
|-------|-------|
| **Severity** | P0 — Critical |
| **CWE** | CWE-94: Code Injection |
| **Grimbard Skill** | `command-injection-anti-pattern` |
| **Location** | `routes/b2bOrder.ts:17-19` |

**Description:**  
User-supplied `orderLinesData` is passed directly to `safeEval()` inside a `vm.runInContext()` sandbox:

```typescript
const sandbox = { safeEval, orderLinesData }
vm.createContext(sandbox)
vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })
```

The `notevil` library's `safeEval` has known sandbox escapes, and `vm.runInContext` is not a security boundary in Node.js.

**Impact:** Arbitrary server-side code execution. Full system compromise. Data exfiltration.

**Remediation:** Never evaluate user-supplied strings. Parse order data as JSON with a strict schema validator.

---

### 4. XXE Injection in File Upload

| Field | Value |
|-------|-------|
| **Severity** | P0 — Critical |
| **CWE** | CWE-611: XML External Entity Injection |
| **Grimbard Skill** | `missing-input-validation-anti-pattern` |
| **Location** | `routes/fileUpload.ts:73-80` |

**Description:**  
XML uploads are parsed with `libxmljs2` with `noent: true`, which expands external entities:

```typescript
vm.runInContext('libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })', sandbox, { timeout: 2000 })
```

An attacker can craft XML with `<!ENTITY xxe SYSTEM "file:///etc/passwd">` to read arbitrary files from the server.

**Impact:** Arbitrary file read (e.g., `/etc/passwd`, application secrets). Denial of service via billion-laughs attack. Potential SSRF.

**Remediation:** Parse XML with `noent: false` (disable entity expansion). Use a safe XML parser or validate against a strict schema.

---

## P1 — High Findings

### 5. Weak Password Hashing (MD5, No Salt)

| Field | Value |
|-------|-------|
| **Severity** | P1 — High |
| **CWE** | CWE-327: Use of Broken Crypto Algorithm / CWE-759: No Salt |
| **Grimbard Skill** | `weak-password-hashing-anti-pattern` |
| **Location** | `lib/insecurity.ts:36`, `models/user.ts:63` |

**Description:**  
Passwords are hashed with unsalted MD5:

```typescript
export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')
```

MD5 is cryptographically broken. Without salting, rainbow tables crack passwords instantly. GPU-based attacks achieve billions of MD5 hashes per second.

**Impact:** Mass credential compromise if database is leaked. Credential stuffing across services.

**Remediation:** Use bcrypt, Argon2, or scrypt with per-user salt and appropriate work factor.

---

### 6. JWT Algorithm Confusion / None Algorithm

| Field | Value |
|-------|-------|
| **Severity** | P1 — High |
| **CWE** | CWE-287: Improper Authentication |
| **Grimbard Skill** | `jwt-misuse-anti-pattern` |
| **Location** | `lib/insecurity.ts:39`, `routes/verify.ts:79-95` |

**Description:**  
The `isAuthorized` middleware uses `express-jwt` with only the public key specified, but the challenge code in `verify.ts` explicitly checks for and accepts JWTs with `alg: "none"` and `alg: "HS256"` (algorithm confusion). The `express-jwt` version in use (0.1.3 per the known-vulnerable-component check) may not enforce algorithm restrictions.

**Impact:** Token forgery. Authentication bypass without knowing the private key.

**Remediation:** Pin the allowed algorithm (`algorithms: ['RS256']`). Upgrade `express-jwt` to a version that rejects `none` algorithm by default.

---

### 7. Missing CSRF Protection on Password Change (GET Method)

| Field | Value |
|-------|-------|
| **Severity** | P1 — High |
| **CWE** | CWE-352: Cross-Site Request Forgery |
| **Grimbard Skill** | `missing-authentication-anti-pattern` |
| **Location** | `routes/changePassword.ts:12`, `server.ts:268` |

**Description:**  
The password change endpoint uses **GET** with query parameters:

```typescript
app.get('/rest/user/change-password', changePassword())
```

```typescript
const currentPassword = query.current as string
const newPassword = query.new as string
```

GET requests are trivially triggered via `<img>` tags or links. Additionally, the `current` password parameter is optional — if omitted, the password is changed without verifying the old one.

**Impact:** Account takeover via CSRF. Any page can change a logged-in user's password by embedding an image tag.

**Remediation:** Use POST/PUT for state-changing operations. Require and validate the current password. Implement CSRF tokens.

---

### 8. Broken Access Control on Basket Retrieval (IDOR)

| Field | Value |
|-------|-------|
| **Severity** | P1 — High |
| **CWE** | CWE-639: Insecure Direct Object Reference |
| **Grimbard Skill** | `authorisation-pattern` |
| **Location** | `routes/basket.ts:14-16` |

**Description:**  
The basket endpoint accepts an arbitrary `id` parameter and returns the basket contents without verifying the basket belongs to the authenticated user:

```typescript
BasketModel.findOne({ where: { id }, include: [{ model: ProductModel, paranoid: false, as: 'Products' }] })
```

The `basketAccessChallenge` code confirms this is intentionally exploitable — it checks if the user's basket ID differs from the requested one.

**Impact:** Any authenticated user can view any other user's shopping basket, exposing purchase data and personal preferences.

**Remediation:** Filter queries by the authenticated user's ID: `where: { id, UserId: authenticatedUser.id }`.

---

### 9. Open Redirect via Allowlist Bypass

| Field | Value |
|-------|-------|
| **Severity** | P1 — High |
| **CWE** | CWE-601: Open Redirect |
| **Grimbard Skill** | `data-validation-pattern` |
| **Location** | `lib/insecurity.ts:104-110` |

**Description:**  
The redirect allowlist check uses `String.includes()`:

```typescript
allowed = allowed || url.includes(allowedUrl)
```

An attacker can bypass this by crafting a URL that *contains* an allowed URL as a substring, e.g., `https://evil.com?https://github.com/juice-shop/juice-shop`.

**Impact:** Phishing attacks using the application's domain as a trusted redirect source.

**Remediation:** Use strict URL parsing. Compare origin/hostname, not substring matching.

---

## P2 — Medium Findings

### 10. Server-Side Template Injection (SSTI) via Data Erasure

| Field | Value |
|-------|-------|
| **Severity** | P2 — Medium |
| **CWE** | CWE-1336: Server-Side Template Injection |
| **Grimbard Skill** | `command-injection-anti-pattern` |
| **Location** | `routes/dataErasure.ts:55-68` |

**Description:**  
The `layout` parameter from the request body is used as a template layout path, and `req.body` is spread into the template context:

```typescript
if (req.body.layout) {
  const filePath: string = path.resolve(req.body.layout).toLowerCase()
  // ...
  res.render('dataErasureResult', { ...req.body }, ...)
}
```

An attacker can inject template expressions via body fields (e.g., `{{constructor.constructor('return this.process')()}}`), and can also control the layout file path for local file read (LFR).

**Impact:** Arbitrary file read on the server. Potential RCE depending on template engine.

**Remediation:** Never use user input as template paths. Whitelist allowed layouts. Never spread unvalidated user input into template context.

---

### 11. Path Traversal in Zip File Upload

| Field | Value |
|-------|-------|
| **Severity** | P2 — Medium |
| **CWE** | CWE-22: Path Traversal |
| **Grimbard Skill** | `path-traversal-anti-pattern` |
| **Location** | `routes/fileUpload.ts:31-44` |

**Description:**  
Zip file entries are extracted with only a partial path check:

```typescript
const absolutePath = path.resolve('uploads/complaints/' + fileName)
if (absolutePath.includes(path.resolve('.'))) {
  entry.pipe(fs.createWriteStream('uploads/complaints/' + fileName))
}
```

The check `absolutePath.includes(path.resolve('.'))` can be bypassed since most resolved paths will include the current directory. The write target `'uploads/complaints/' + fileName` uses unsanitized zip entry names that can contain `../`.

**Impact:** Arbitrary file write. Overwrite application files (e.g., `ftp/legal.md` as the challenge demonstrates).

**Remediation:** Validate that the resolved extraction path starts with the intended directory using `path.resolve(target).startsWith(baseDir)`.

---

### 12. YAML Deserialization Bomb

| Field | Value |
|-------|-------|
| **Severity** | P2 — Medium |
| **CWE** | CWE-502: Deserialization of Untrusted Data |
| **Grimbard Skill** | `missing-input-validation-anti-pattern` |
| **Location** | `routes/fileUpload.ts:100-105` |

**Description:**  
YAML files are parsed with `yaml.load()` (unsafe by default in js-yaml < 4.x) which can trigger billion-laughs-style expansion via YAML anchors and aliases, causing denial of service:

```typescript
vm.runInContext('JSON.stringify(yaml.load(data))', sandbox, { timeout: 2000 })
```

**Impact:** Denial of service. Memory exhaustion. Potential code execution via YAML deserialization gadgets (depending on js-yaml version).

**Remediation:** Use `yaml.load()` with `schema: yaml.SAFE_SCHEMA` or use `yaml.safeLoad()`. Validate file size limits before parsing.

---

### 13. Sensitive Data in JSONP Response (XSS via Callback)

| Field | Value |
|-------|-------|
| **Severity** | P2 — Medium |
| **CWE** | CWE-79: Cross-Site Scripting |
| **Grimbard Skill** | `xss-anti-pattern` |
| **Location** | `routes/currentUser.ts:18-22` |

**Description:**  
The `/rest/user/whoami` endpoint supports JSONP when a `callback` query parameter is provided:

```typescript
if (req.query.callback === undefined) {
  res.json(response)
} else {
  res.jsonp(response)
}
```

JSONP responses bypass Same-Origin Policy, allowing any website to read the authenticated user's email, ID, and profile data by including a `<script>` tag pointing to this endpoint.

**Impact:** User information disclosure cross-origin. Email enumeration. Can be chained with other attacks.

**Remediation:** Remove JSONP support. Use CORS with strict origin allowlisting instead.

---

### 15. Stored XSS via Username in Profile Page (with eval and CSP Bypass)

| Field | Value |
|-------|-------|
| **Severity** | P1 — High |
| **CWE** | CWE-79: Cross-Site Scripting (Stored) |
| **Grimbard Skill** | `xss-anti-pattern` |
| **Location** | `routes/userProfile.ts:58-66`, `routes/userProfile.ts:86-87` |

**Description:**  
The user profile page renders the username into a Pug template via string replacement — without sanitization:

```typescript
template = template.replace(/_username_/g, username)
```

Worse, if the username matches `#{(...)}`, it is passed to `eval()`:

```typescript
username = eval(code)
```

Additionally, the CSP header is built using the user's `profileImage` field:

```typescript
const CSP = `img-src 'self' ${user?.profileImage}; script-src 'self' 'unsafe-eval' ...`
```

An attacker can set their profile image to `; script-src 'unsafe-inline'` to bypass CSP, then set their username to `<script>alert('xss')</script>` for stored XSS that executes for anyone viewing the profile.

**Impact:** Stored XSS affecting any user who views the attacker's profile. Session hijacking, account takeover, defacement. The `eval()` path enables server-side code execution.

**Remediation:** Never use string replacement to inject user data into templates — use template engine's built-in escaping. Remove `eval()` entirely. Never construct CSP headers from user-controlled data.

---

### 16. DOM XSS via Video Subtitles Injection

| Field | Value |
|-------|-------|
| **Severity** | P2 — Medium |
| **CWE** | CWE-79: Cross-Site Scripting (DOM-based) |
| **Grimbard Skill** | `xss-anti-pattern` |
| **Location** | `routes/videoHandler.ts:64-65` |

**Description:**  
Subtitle file contents are injected directly into a `<script>` tag in the rendered HTML:

```typescript
compiledTemplate = compiledTemplate.replace(
  '<script id="subtitle"></script>',
  '<script id="subtitle" ...>' + subs + '</script>'
)
```

If the subtitle file (or its config path) can be manipulated, `</script><script>alert('xss')</script>` breaks out of the script tag and executes arbitrary JavaScript.

**Impact:** XSS via crafted subtitle content. Session hijacking for users viewing the promotion page.

**Remediation:** HTML-encode subtitle content before injection, or load subtitles via a separate request with proper Content-Type.

---

## P3 — Low Findings

### 14. Overly Permissive CORS Configuration

| Field | Value |
|-------|-------|
| **Severity** | P3 — Low |
| **CWE** | CWE-942: Overly Permissive CORS Policy |
| **Grimbard Skill** | `open-cors-anti-pattern` |
| **Location** | `server.ts:134-135` |

**Description:**  
CORS is configured to allow all origins:

```typescript
app.options('*', cors())
app.use(cors())
```

Combined with cookie-based authentication, this allows any website to make authenticated API requests on behalf of logged-in users.

**Impact:** Enables cross-origin attacks when combined with other vulnerabilities. Facilitates data theft from authenticated endpoints.

**Remediation:** Configure CORS with an explicit origin allowlist matching trusted frontend domains.

---

## Summary Table

| # | Finding | Severity | CWE | Grimbard Skill | Location |
|---|---------|----------|-----|----------------|----------|
| 1 | SQL Injection in Login | P0 | CWE-89 | `sql-injection-anti-pattern` | `routes/login.ts:30` |
| 2 | Hardcoded RSA Private Key | P0 | CWE-798 | `hardcoded-secrets-anti-pattern` | `lib/insecurity.ts:21` |
| 3 | RCE via B2B Order Eval | P0 | CWE-94 | `command-injection-anti-pattern` | `routes/b2bOrder.ts:17` |
| 4 | XXE in XML File Upload | P0 | CWE-611 | `missing-input-validation-anti-pattern` | `routes/fileUpload.ts:73` |
| 5 | MD5 Password Hashing (No Salt) | P1 | CWE-327 | `weak-password-hashing-anti-pattern` | `lib/insecurity.ts:36` |
| 6 | JWT Algorithm Confusion | P1 | CWE-287 | `jwt-misuse-anti-pattern` | `lib/insecurity.ts:39` |
| 7 | CSRF on Password Change (GET) | P1 | CWE-352 | `missing-authentication-anti-pattern` | `routes/changePassword.ts:12` |
| 8 | IDOR on Basket Access | P1 | CWE-639 | `authorisation-pattern` | `routes/basket.ts:14` |
| 9 | Open Redirect Allowlist Bypass | P1 | CWE-601 | `data-validation-pattern` | `lib/insecurity.ts:104` |
| 10 | SSTI via Data Erasure | P2 | CWE-1336 | `command-injection-anti-pattern` | `routes/dataErasure.ts:55` |
| 11 | Path Traversal in Zip Upload | P2 | CWE-22 | `path-traversal-anti-pattern` | `routes/fileUpload.ts:31` |
| 12 | YAML Deserialization Bomb | P2 | CWE-502 | `missing-input-validation-anti-pattern` | `routes/fileUpload.ts:100` |
| 13 | JSONP User Data Leak | P2 | CWE-79 | `xss-anti-pattern` | `routes/currentUser.ts:18` |
| 14 | Overly Permissive CORS | P3 | CWE-942 | `open-cors-anti-pattern` | `server.ts:134` |
| 15 | Stored XSS via Username + CSP Bypass | P1 | CWE-79 | `xss-anti-pattern` | `routes/userProfile.ts:58` |
| 16 | DOM XSS via Video Subtitles | P2 | CWE-79 | `xss-anti-pattern` | `routes/videoHandler.ts:64` |

---

## Methodology Note

This review was conducted using **grimbard** security pattern analysis. Each finding maps to a grimbard skill — a codified security pattern or anti-pattern that encodes expert knowledge into reusable detection logic. The skills referenced above are available in the [grimbard skills directory](../skills/) and can be used by AI agents to automatically detect these vulnerability classes during code review.

OWASP Juice Shop is an *intentionally vulnerable* application designed for security training. The vulnerabilities documented here are **deliberate** and serve as learning exercises. This review demonstrates that grimbard's pattern-based approach successfully identifies all major vulnerability classes present in the application.
