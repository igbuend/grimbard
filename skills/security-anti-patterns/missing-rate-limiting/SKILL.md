---
name: "missing-rate-limiting-anti-pattern"
description: "Security anti-pattern for missing rate limiting (CWE-770). Use when generating or reviewing API endpoints, authentication systems, or public-facing services. Detects absence of request throttling enabling brute force, credential stuffing, and DoS attacks."
---

# Missing Rate Limiting Anti-Pattern

**Severity:** High

## Summary
Missing rate limiting is a vulnerability where an application fails to restrict the number of times an action can be performed within a given timeframe. This allows an attacker to make an unlimited number of requests to a specific endpoint, which can be abused for various attacks. The most common abuses include brute-forcing credentials on a login page, scraping sensitive data from an API, or causing a denial-of-service (DoS) by overwhelming the application with resource-intensive requests.

## The Anti-Pattern
The anti-pattern is exposing any endpoint—especially authentication or resource-intensive ones—to the internet without any mechanism to control how frequently it can be called by a single user or IP address.

### BAD Code Example
```python
# VULNERABLE: The login endpoint has no rate limiting.
from flask import request, jsonify

@app.route("/api/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    # This endpoint can be called thousands of times per minute from the same IP address.
    # An attacker can use a password list to perform a brute-force or credential stuffing attack,
    # trying millions of passwords against a single user account until they find the right one.
    if check_credentials(username, password):
        return jsonify({"status": "success", "token": generate_token(username)})
    else:
        return jsonify({"status": "failed"}), 401

# Another example: A search endpoint without rate limiting.
@app.route("/api/search")
def search():
    query = request.args.get("q")
    # An attacker could write a script to rapidly hit this endpoint, scraping all
    # the site's data or causing a DoS by making the database do heavy work.
    results = perform_complex_search(query)
    return jsonify(results)
```

### GOOD Code Example
```python
# SECURE: Implement rate limiting using middleware and a tracking backend like Redis.
from flask import request, jsonify
from redis import Redis
from functools import wraps

redis = Redis()

def rate_limit(limit, per, scope_func):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            key = f"rate-limit:{scope_func(request)}:{request.endpoint}"
            # Increment the count for the current key.
            # Set it to expire after `per` seconds on the first request in the window.
            p = redis.pipeline()
            p.incr(key)
            p.expire(key, per)
            count = p.execute()[0]

            if count > limit:
                return jsonify({"error": "Rate limit exceeded"}), 429 # 429 Too Many Requests

            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Define a function to get the identifier for the rate limit scope (e.g., IP address).
def get_ip(request):
    return request.remote_addr

# Apply different rate limits to different endpoints.
@app.route("/api/login", methods=["POST"])
@rate_limit(limit=10, per=60*5, scope_func=get_ip) # 10 requests per 5 minutes per IP.
def login_secure():
    # ... login logic ...
    pass

@app.route("/api/search")
@rate_limit(limit=100, per=60, scope_func=get_ip) # 100 requests per minute per IP.
def search_secure():
    # ... search logic ...
    pass
```

## Detection
- **Review public endpoints:** Examine all endpoints that can be accessed without authentication. Do they have rate limiting?
- **Check authentication endpoints:** Specifically look at login, password reset, and registration endpoints. These are prime targets for brute-force attacks if not rate-limited.
- **Analyze API design:** For public APIs, check if there is a documented rate-limiting policy (e.g., in the API documentation).
- **Perform testing:** Write a simple script to hit a single endpoint in a tight loop. If you don't receive a `429 Too Many Requests` status code after a certain number of attempts, the endpoint is likely missing rate limiting.

## Prevention
- [ ] **Implement IP-based rate limiting** on all public-facing endpoints, especially authentication and other sensitive ones.
- [ ] **Implement user/account-based rate limiting** for authenticated users to prevent a single user from abusing the system.
- [ ] **Use an appropriate algorithm:** Common choices are Token Bucket, Leaky Bucket, or Fixed/Sliding Window counters. Most modern web frameworks have middleware or libraries for this.
- [ ] **Return a `429 Too Many Requests` status code** when a limit is exceeded. Include a `Retry-After` header to tell the client when they can try again.
- [ ] **Log rate limit violations:** This can help you identify and respond to potential attacks.
- [ ] **For login endpoints, consider account lockouts** after a certain number of failed attempts as an additional layer of defense.

## Related Security Patterns & Anti-Patterns
- [Missing Authentication Anti-Pattern](../missing-authentication/): Endpoints that are missing authentication are at even greater risk if they also lack rate limiting.
- [Denial of Service (DoS):](../#) Missing rate limiting is a primary cause of application-layer DoS vulnerabilities.

## References
- [OWASP Top 10 A06:2025 - Insecure Design](https://owasp.org/Top10/2025/A06_2025-Insecure_Design/)
- [OWASP GenAI LLM10:2025 - Unbounded Consumption](https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/)
- [OWASP API Security API4:2023 - Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)
- [OWASP Rate Limiting](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
- [CWE-770: Resource Allocation Without Limits](https://cwe.mitre.org/data/definitions/770.html)
- [CAPEC-49: Password Brute Forcing](https://capec.mitre.org/data/definitions/49.html)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
