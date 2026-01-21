---
name: "excessive-data-exposure-anti-pattern"
description: "Security anti-pattern for excessive data exposure (CWE-200). Use when generating or reviewing API responses, database queries, or data serialization. Detects returning more data than necessary including internal fields, sensitive attributes, and related records."
---

# Excessive Data Exposure Anti-Pattern

**Severity:** High

## Summary

Excessive Data Exposure is a common vulnerability where an application, particularly an API, reveals more information than is necessary for the client to function. This anti-pattern often occurs when an API endpoint returns a raw database object or a model class directly, without filtering out sensitive or internal fields. Even if the client-side UI hides this data, an attacker can easily intercept the API response to access it, leading to the exposure of personal information (PII), credentials, and internal system details.

## The Anti-Pattern

The anti-pattern is to serialize and return an entire object from a database or internal model, assuming the client will pick what it needs. This sends all properties of the object, including sensitive ones, over the wire.

### BAD Code Example

```python
# VULNERABLE: Returns the entire raw database user object.
from flask import jsonify

class User:
    def __init__(self, id, username, email, password_hash, ssn, is_admin):
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.ssn = ssn
        self.is_admin = is_admin

    def to_dict(self):
        # This method dumps all object properties, including sensitive ones.
        return self.__dict__

@app.route("/api/users/<int:user_id>")
def get_user(user_id):
    user = find_user_by_id(user_id) # Imagine this retrieves a User object.
    if not user:
        return jsonify({"error": "User not found"}), 404

    # The entire object is serialized and returned, exposing password_hash, ssn, etc.
    return jsonify(user.to_dict())
```

### GOOD Code Example

```python
# SECURE: Use a Data Transfer Object (DTO) to explicitly define the API response structure.
from flask import jsonify

class User: # Same User class as before
    # ...
    pass

class UserPublicDTO:
    def __init__(self, id, username):
        self.id = id
        self.username = username

    @staticmethod
    def from_model(user):
        return UserPublicDTO(id=user.id, username=user.username)

@app.route("/api/users/<int:user_id>")
def get_user(user_id):
    user = find_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # The User object is transformed into a safe DTO.
    # Only the `id` and `username` fields are included in the response.
    user_dto = UserPublicDTO.from_model(user)
    return jsonify(user_dto.__dict__)
```

## Detection

- **Review API responses:** Look for endpoints that return large, complex JSON objects. Check if these objects contain fields that are not used by the front-end application or that seem internal or sensitive (e.g., `passwordHash`, `ssn`, `internalNotes`).
- **Analyze database queries:** Search for `SELECT *` queries that feed directly into API responses.
- **Inspect serialization logic:** Look for generic `.toJSON()` or `serialize()` methods on model objects that dump all properties without a filter.

## Prevention

- [ ] **Use Data Transfer Objects (DTOs)** or ViewModels with an explicit allowlist of fields for every API response.
- [ ] **Never return raw database or ORM objects** directly from an API endpoint.
- [ ] **Select only the required columns** in your database queries (`SELECT id, username FROM ...` instead of `SELECT *`).
- [ ] **Implement field-level authorization** based on the user's permissions. For example, a user might see their own email address, but other users cannot.
- [ ] **Filter on the server, not the client.** Never rely on the client-side application to filter out sensitive data.
- [ ] **Define different DTOs for different access levels** (e.g., a `UserPublicDTO` for public profiles and a `UserPrivateDTO` for a user viewing their own data).

## Related Security Patterns & Anti-Patterns

- [Missing Authentication Anti-Pattern](../missing-authentication/): If an endpoint is missing authentication, excessive data exposure becomes even more dangerous.
- [Mass Assignment Anti-Pattern](../mass-assignment/): The inverse of this problem, where an API accepts more data than it should, leading to unauthorized modifications.

## References

- [OWASP Top 10 A01:2025 - Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/)
- [OWASP GenAI LLM02:2025 - Sensitive Information Disclosure](https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/)
- [OWASP API Security API3:2023 - Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)
- [CWE-200: Information Exposure](https://cwe.mitre.org/data/definitions/200.html)
- [CAPEC-37: Retrieve Embedded Sensitive Data](https://capec.mitre.org/data/definitions/37.html)
- [PortSwigger: Information Disclosure](https://portswigger.net/web-security/information-disclosure)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
