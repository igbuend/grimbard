---
name: "session-fixation-anti-pattern"
description: "Security anti-pattern for session fixation vulnerabilities (CWE-384). Use when generating or reviewing code that handles user sessions, login flows, or authentication state changes. Detects failure to regenerate session IDs after authentication."
---

# Session Fixation Anti-Pattern

**Severity:** High

## Summary
Session fixation is a type of session hijacking attack where an attacker "fixes" a user's session ID before the user logs in. The attacker first obtains a valid session ID from the application (e.g., by visiting the login page). Then, they trick the victim into using this pre-determined session ID to log in. Because the application fails to generate a new session ID after successful authentication, the victim becomes logged into the attacker's chosen session. The attacker, still possessing the original session ID, can then hijack the victim's authenticated session.

## The Anti-Pattern
The anti-pattern is an application that uses the same session identifier before and after a user authenticates.

### BAD Code Example
```python
# VULNERABLE: The session ID is not regenerated after successful login.
from flask import Flask, session, redirect, url_for, request

app = Flask(__name__)
app.secret_key = 'your_secret_key' # Insecure in production

# Attacker visits this page, gets a session ID, e.g., 'attacker_session_id'.
@app.route('/')
def index():
    if 'username' in session:
        return f'Hello {session["username"]}! <a href="/logout">Logout</a>'
    return 'Welcome, please <a href="/login">Login</a>'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if check_credentials(username, password):
            # CRITICAL FLAW: The session ID is not regenerated here.
            # The existing session, potentially fixed by an attacker, is now authenticated.
            session['username'] = username
            return redirect(url_for('index'))
        return 'Invalid credentials'
    return '''
        <form method="post">
            <p><input type=text name=username></p>
            <p><input type=password name=password></p>
            <p><input type=submit value=Login></p>
        </form>
    '''

# Attacker Scenario:
# 1. Attacker visits `http://vulnerable-app.com/`. The server assigns a session ID, e.g., `session_id=ABCD`.
# 2. Attacker crafts a phishing link: `http://vulnerable-app.com/login?session_id=ABCD`.
#    (Note: Modern browsers prevent injecting session IDs via URL, but other techniques exist, e.g., via referrer, HTTP response splitting, or exploiting XSS).
# 3. Attacker sends the link to the victim.
# 4. Victim clicks the link, their browser uses `session_id=ABCD`.
# 5. Victim logs in. The server authenticates the victim but *reuses* `session_id=ABCD`.
# 6. Attacker, still holding `session_id=ABCD`, now accesses the victim's authenticated session.
```

### GOOD Code Example
```python
# SECURE: Regenerate the session ID after successful login and on privilege changes.
from flask import Flask, session, redirect, url_for, request

app = Flask(__name__)
app.secret_key = 'your_secret_key' # Use a strong, securely managed key

@app.route('/')
def index_secure():
    if 'username' in session:
        return f'Hello {session["username"]}! <a href="/logout">Logout</a>'
    return 'Welcome, please <a href="/login_secure">Login Securely</a>'

@app.route('/login_secure', methods=['GET', 'POST'])
def login_secure():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if check_credentials(username, password):
            # CRITICAL: Regenerate the session ID after successful authentication.
            # This creates a new session, invalidating any pre-login session ID.
            session.regenerate() # Flask's way to generate a new session ID.
            session['username'] = username
            return redirect(url_for('index_secure'))
        return 'Invalid credentials'
    return '''
        <form method="post">
            <p><input type=text name=username></p>
            <p><input type=password name=password></p>
            <p><input type=submit value=Login></p>
        </form>
    '''

@app.route('/logout')
def logout():
    session.clear() # Invalidate session data.
    session.regenerate() # Regenerate session ID to prevent reuse.
    return redirect(url_for('index_secure'))
```

## Detection
- **Review login flows:** Trace the code paths involved in user authentication. Verify that after a successful login, the application explicitly invalidates the old session and generates a completely new session ID.
- **Check session management libraries:** Understand how your web framework or session management library handles session ID generation and regeneration. Ensure it's used correctly.
- **Test with a fixed session ID:** Manually attempt to set a session ID (e.g., using browser developer tools or a proxy like Burp Suite) before logging in. After logging in, check if the session ID remains the same.

## Prevention
- [ ] **Regenerate the session ID after any change in the user's authentication state,** especially after a successful login. This creates a new session, effectively invalidating any pre-login session ID an attacker might have fixed.
- [ ] **Regenerate the session ID on privilege level changes** (e.g., when a user promotes themselves to administrator).
- [ ] **Invalidate the old session** on the server-side when a new session is created.
- [ ] **Ensure session cookies are set with secure flags:**
    - `HttpOnly`: Prevents client-side scripts from accessing the cookie.
    - `Secure`: Ensures the cookie is only sent over HTTPS.
    - `SameSite`: Helps prevent CSRF attacks.
- [ ] **Implement session timeouts:** Both absolute timeouts and idle timeouts should be used to limit the window of opportunity for an attacker.

## Related Security Patterns & Anti-Patterns
- [Missing Authentication Anti-Pattern](../missing-authentication/): The foundation of secure user management, without which session fixation is more easily exploited.
- [JWT Misuse Anti-Pattern](../jwt-misuse/): When using JWTs, token revocation and expiration become crucial for managing session state securely.
- [Insufficient Randomness Anti-Pattern](../insufficient-randomness/): Session IDs must be generated using a cryptographically secure random number generator to prevent prediction.

## References
- [OWASP Top 10 A07:2025 - Authentication Failures](https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/)
- [OWASP GenAI LLM06:2025 - Excessive Agency](https://genai.owasp.org/llmrisk/llm06-excessive-agency/)
- [OWASP API Security API2:2023 - Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
- [CAPEC-61: Session Fixation](https://capec.mitre.org/data/definitions/61.html)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
