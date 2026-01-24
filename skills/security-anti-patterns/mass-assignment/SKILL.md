---
name: "mass-assignment-anti-pattern"
description: "Security anti-pattern for mass assignment vulnerabilities (CWE-915). Use when generating or reviewing code that creates or updates objects from user input, form handling, or API request processing. Detects uncontrolled property binding enabling privilege escalation."
---

# Mass Assignment Anti-Pattern

**Severity:** High

## Summary

Mass assignment (autobinding) occurs when frameworks automatically bind HTTP parameters to object properties without filtering. Attackers inject unauthorized properties (`isAdmin: true`) to escalate privileges or modify protected fields. This vulnerability enables complete access control bypass through parameter injection.

## The Anti-Pattern

Never use user-provided data dictionaries to update models without filtering for allowed properties. Use explicit allowlists.

### BAD Code Example

```python
# VULNERABLE: The incoming request data is used directly to update the user model.
from flask import request
from db import User, session

@app.route("/api/users/me", methods=["POST"])
def update_profile():
    # Assume user is already authenticated.
    user = get_current_user()

    # Attacker crafts a JSON body:
    # {
    #   "email": "new.email@example.com",
    #   "is_admin": true
    # }
    request_data = request.get_json()

    # Many ORMs allow updating an object from a dictionary.
    # If the User model has an `is_admin` property, it will be updated here.
    for key, value in request_data.items():
        setattr(user, key, value) # Direct, unsafe assignment.

    session.commit()
    return {"message": "Profile updated."}

# The attacker has just made themselves an administrator.
```

### GOOD Code Example

```python
# SECURE: Use a Data Transfer Object (DTO) or an explicit allowlist to control which fields can be updated.
from flask import request
from db import User, session

# Option 1: Use an allowlist of fields.
ALLOWED_UPDATE_FIELDS = {"email", "first_name", "last_name"}

@app.route("/api/users/me", methods=["POST"])
def update_profile_allowlist():
    user = get_current_user()
    request_data = request.get_json()

    for key, value in request_data.items():
        # Only update the attribute if it's in our explicit allowlist.
        if key in ALLOWED_UPDATE_FIELDS:
            setattr(user, key, value)

    session.commit()
    return {"message": "Profile updated."}


# Option 2 (Better): Use a DTO or schema to define and validate the input.
from pydantic import BaseModel, EmailStr

class UserUpdateDTO(BaseModel):
    # This class defines the *only* fields that can be submitted.
    # The `is_admin` field is not here, so it can't be set by the user.
    email: EmailStr
    first_name: str
    last_name: str

@app.route("/api/users/me/dto", methods=["POST"])
def update_profile_dto():
    user = get_current_user()
    try:
        # Pydantic will raise a validation error if extra fields like `is_admin` are present.
        update_data = UserUpdateDTO(**request.get_json())
    except ValidationError as e:
        return {"error": str(e)}, 400

    user.email = update_data.email
    user.first_name = update_data.first_name
    user.last_name = update_data.last_name
    session.commit()
    return {"message": "Profile updated."}
```

## Detection

- **Find direct model updates from request data:** Grep for unsafe binding:
  - `rg 'setattr.*request\.|\.update\(request\.' --type py`
  - `rg 'Object\.assign.*req\.body|\.save\(req\.body' --type js`
  - `rg 'BeanUtils\.copyProperties|ModelMapper' --type java`
- **Identify blocklist approaches (insecure):** Find key deletion patterns:
  - `rg 'del.*\[.*(admin|role|permission)|\.pop\(.*(admin|role)' --type py`
  - `rg 'delete.*\.(isAdmin|role)|omit\(' --type js`
  - Blocklists are insecure - search for allowlist patterns instead
- **Test for mass assignment:** Send malicious parameters:
  - `curl -X POST /api/users -d '{"email":"test@example.com","isAdmin":true}'`
  - Try: `isAdmin`, `role`, `permissions`, `accountBalance`, `verified`
- **Check for DTO usage:** Verify proper input validation:
  - `rg 'class.*DTO|@Valid|validator\.validate' --type py --type java`

## Prevention

- [ ] **Use an allowlist approach:** Never use a blocklist to filter incoming data. Always use an allowlist of properties that are permitted to be set by the user.
- [ ] **Use Data Transfer Objects (DTOs)** or dedicated input schemas to strictly define the expected request body. This is the most robust solution.
- [ ] **Set sensitive properties explicitly** in your code, outside of any mass assignment operation (e.g., `new_user.is_admin = False`).
- [ ] **Be aware of framework features:** Some frameworks have built-in protections against mass assignment. Understand how to use them correctly.

## Related Security Patterns & Anti-Patterns

- [Excessive Data Exposure Anti-Pattern](../excessive-data-exposure/): The inverse of mass assignment. Instead of accepting too much data, the application returns too much data.
- [Missing Authentication Anti-Pattern](../missing-authentication/): If an endpoint is also missing proper authentication, mass assignment becomes even more dangerous, as an unauthenticated user could modify any object.

## References

- [OWASP Top 10 A01:2025 - Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/)
- [OWASP GenAI LLM06:2025 - Excessive Agency](https://genai.owasp.org/llmrisk/llm06-excessive-agency/)
- [OWASP API Security API3:2023 - Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)
- [OWASP Mass Assignment](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [CWE-915: Mass Assignment](https://cwe.mitre.org/data/definitions/915.html)
- [CAPEC-114: Authentication Abuse](https://capec.mitre.org/data/definitions/114.html)
- [PortSwigger: Api Testing](https://portswigger.net/web-security/api-testing)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
