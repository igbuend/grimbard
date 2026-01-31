---
name: data-validation
description: Security pattern for input validation and sanitization. Use when implementing input handling, preventing injection attacks (SQL, XSS, command), ensuring data integrity, or processing data from untrusted sources. Addresses "Entity provides unexpected data" problem.
---

# Data Validation Security Pattern

Ensures all incoming data is validated against specifications before processing, preventing injection attacks, data corruption, and unexpected behavior.

## When to Use

Use this pattern when:

- Processing ANY input from external sources (users, APIs, databases)
- Preventing injection attacks (SQLi, XSS, Command Injection)
- Implementing API request validation checklists
- Ensuring data integrity for business logic
- Handling file uploads or complex data structures

## Problem Addressed

**Entity provides unexpected data**: Malicious or malformed input causes:

- Injection attacks (SQL, XSS, command injection)
- System crashes or unexpected behavior
- Data corruption
- Security bypasses

## Core Components

| Role | Type | Responsibility |
|------|------|----------------|
| **Entity** | Entity | Sends data to system |
| **Enforcer** | Enforcement Point | Intercepts all incoming data |
| **Validator** | Decision Point | Validates data against specification |
| **Specification Provider** | Information Point | Manages validation rules |
| **System** | Entity | Processes validated data |

### Data Elements

- **data**: Input from entity (raw)
- **canonical_data**: Normalized, validated form
- **specification**: Rules defining valid data
- **type**: Identifier for applicable specification
- **error**: Validation failure message

## Validation Flow

```
Entity → [data] → Enforcer
Enforcer → [data] → Validator
Validator → [get_specification(type)] → Specification Provider
Specification Provider → [specification] → Validator
Validator → [validate, transform to canonical] → Validator
Validator → [canonical_data or error] → Enforcer
Enforcer → [canonical_data] → System (if valid)
        → [error] → Entity (if invalid)
```

1. Enforcer intercepts ALL incoming data
2. Validator retrieves appropriate specification
3. Validator transforms to canonical form
4. Validator checks against specification
5. Valid: canonical data forwarded to System
6. Invalid: error returned to Entity

## Validation Principles

### Validate Everything

- All data from uncontrolled sources
- Parameters, headers, cookies, files
- Data from APIs, databases (defense in depth)

### Canonical Form

Transform data to standardized form:

- Remove/escape special characters
- Decode encoded values
- Normalize Unicode
- Parse structured data to typed objects

**Benefit**: System only processes data in known format.

### Allowlist vs. Blocklist

- **Allowlist (preferred)**: Define what IS allowed
- **Blocklist (risky)**: Define what is NOT allowed

Blocklists fail against unknown attack patterns. Use allowlists.

### Validate Early, Validate Often

- Validate at system boundary (earliest point)
- Re-validate near code that relies on data
- Defense in depth

## Validation Types

### Type Validation

- Ensure data matches expected type
- Integer, string, boolean, date, email, URL

### Range/Length Validation

- Numeric bounds
- String length limits
- Array size limits

### Format Validation

- Regular expressions (carefully!)
- Structural patterns
- Protocol conformance

### Business Logic Validation

- Application-specific rules
- Cross-field validation
- State-dependent validation

## Security Considerations

### Validation ≠ Authorization

- Validation: Is this data well-formed?
- Authorization: Is entity allowed to use this data?

Both are required. Valid data doesn't mean authorized access.

### Error Messages

- Don't reveal validation internals to attackers
- Log detailed errors server-side
- Return generic errors to clients

### Encoding Output

Validation alone doesn't prevent all injection:

- Still encode output for context (HTML, SQL, etc.)
- Use parameterized queries
- Use context-appropriate escaping

### File Uploads

Special validation needed:

- Verify content type (not just extension)
- Scan for malware
- Restrict file sizes
- Store outside web root

### Structured Data (JSON, XML)

- Parse with secure parser
- Disable external entity processing (XXE)
- Validate against schema
- Limit nesting depth

### Regular Expression Safety

- Avoid ReDoS-vulnerable patterns
- Limit input length before regex
- Test regex performance with malicious input

## Common Validation Scenarios

| Input Type | Validations |
|------------|-------------|
| Username | Length, allowed characters, no control chars |
| Email | Format, length, allowlist domains (if applicable) |
| Integer | Type, range, positive/negative |
| URL | Protocol allowlist, format, no javascript: |
| File | Extension, content-type, size, malware scan |
| JSON | Schema validation, depth limits, size limits |

## Implementation Examples

### Python (Pydantic / Flask)

**BAD (Vulnerable):**

```python
# ❌ VULNERABILITY: Manual, incomplete validation
@app.route("/user", methods=["POST"])
def create_user():
    data = request.get_json()
    if 'email' not in data: # What about type? Length? format?
        return "Missing email", 400
    # ... proceeding to use data['age'] which might be a string or negative
```

**GOOD (Secure):**

```python
from pydantic import BaseModel, EmailStr, conint, constr

# ✅ Define strict schema
class UserSchema(BaseModel):
    username: constr(min_length=3, max_length=50, pattern=r'^[a-zA-Z0-9_]+$')
    email: EmailStr
    age: conint(ge=18, le=120)

@app.route("/user", methods=["POST"])
def create_user():
    try:
        # ✅ Validate payload against schema
        user = UserSchema(**request.get_json())
        save_to_db(user.model_dump())
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
```

### JavaScript (Zod / Express)

**BAD (Vulnerable):**

```javascript
// ❌ VULNERABILITY: Implicit trust
app.post('/api/profile', (req, res) => {
    // trusting req.body.website is a valid URL
    // trusting req.body.role is not "admin"
    updateProfile(req.user.id, req.body);
});
```

**GOOD (Secure):**

```javascript
const { z } = require('zod');

// ✅ Define strict schema
const ProfileSchema = z.object({
    website: z.string().url().max(100),
    bio: z.string().max(500).optional(),
    role: z.enum(['user', 'editor']), // Block 'admin'
});

app.post('/api/profile', (req, res) => {
    const result = ProfileSchema.safeParse(req.body);

    if (!result.success) {
        return res.status(400).json(result.error);
    }

    // ✅ Apply canonical/validated data
    updateProfile(req.user.id, result.data);
});
```

## Implementation Checklist

- [ ] All entry points have validation
- [ ] Canonical form transformation
- [ ] Allowlist-based rules
- [ ] Type checking
- [ ] Length/range limits
- [ ] Business rule validation
- [ ] Secure error handling
- [ ] Output encoding (separate from validation)
- [ ] File upload validation
- [ ] Structured data parsing safely
- [ ] Re-validation near sensitive operations

## Related Patterns

- Authorisation (validation doesn't replace authorization)
- Selective encrypted transmission (protect data in transit)
- Log entity actions (log validation failures)

## References

- Source: <https://securitypatterns.distrinet-research.be/patterns/04_01_001__data_validation/>
- OWASP Input Validation Cheat Sheet
- OWASP XSS Prevention Cheat Sheet
