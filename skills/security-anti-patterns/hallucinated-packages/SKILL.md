---
name: hallucinated-packages-anti-pattern
description: Security anti-pattern for hallucinated (non-existent) packages (CWE-1357). Use when generating or reviewing AI-assisted code that imports packages, dependencies, or libraries. CRITICAL AI-specific vulnerability with 5-21% hallucination rate. Detects dependency confusion and slopsquatting risks.
---

# Hallucinated Packages Anti-Pattern

**CWE:** CWE-1357 (Reliance on Unverified Package)
**CAPEC:** [CAPEC-538: Open-Source Library Manipulation](https://capec.mitre.org/data/definitions/538.html)
**Severity:** Critical
**OWASP:** A06:2021 - Vulnerable and Outdated Components

## Risk

AI models hallucinate package names that don't exist, which attackers register on package registries ("slopsquatting"). When developers install these suggested packages, they execute attacker-controlled code. This leads to:

- Supply chain compromise
- Malware execution
- Credential theft
- Backdoor installation

**Statistics:**
- **5-21%** of AI-suggested packages don't exist
- **21.7%** hallucination rate observed for package names in some domains
- Over **2,500** malicious packages discovered on npm in a single study

## BAD Pattern: Blindly Installing AI-Suggested Packages

```pseudocode
// AI suggests this code:

// "Install the flask-auth-secure package for authentication"
// pip install flask-auth-secure

import flask_auth_secure  // This package doesn't exist!

FUNCTION setup_auth(app):
    // If attacker registered flask-auth-secure, their code runs here
    flask_auth_secure.init_app(app)
END FUNCTION

// Real packages: flask-login, flask-security, authlib
```

## GOOD Pattern: Verify Packages Before Installation

```pseudocode
// SECURE: Verify package exists and is legitimate

FUNCTION verify_package(package_name, registry="npm"):
    // 1. Check if package exists on registry
    response = http.get(registry + "/package/" + package_name)

    IF response.status == 404:
        log.warning("Package not found: " + package_name)
        RETURN {exists: FALSE, verified: FALSE}
    END IF

    package_info = response.json()

    // 2. Check package age (new packages are suspicious)
    IF package_info.created_date > 30_DAYS_AGO:
        log.warning("Recently created package: " + package_name)
    END IF

    // 3. Check download count (low downloads = suspicious)
    IF package_info.weekly_downloads < 100:
        log.warning("Low download count: " + package_name)
    END IF

    // 4. Check maintainer reputation
    IF package_info.maintainer NOT IN trusted_maintainers:
        log.warning("Unknown maintainer: " + package_info.maintainer)
    END IF

    // 5. Check for typosquatting of popular packages
    similar = find_similar_packages(package_name)
    IF similar.length > 0:
        log.warning("Similar packages exist: " + similar.join(", "))
    END IF

    RETURN {
        exists: TRUE,
        verified: package_info.weekly_downloads > 1000,
        warnings: warnings
    }
END FUNCTION
```

## Common Hallucinated Package Patterns

| AI Suggests | Real Package |
|-------------|--------------|
| `flask-auth-secure` | `flask-login`, `flask-security` |
| `react-auth-helper` | `react-oauth2-hook`, `@auth0/auth0-react` |
| `python-mysql-utils` | `mysql-connector-python`, `PyMySQL` |
| `express-validate` | `express-validator` |
| `django-rest-auth` | `dj-rest-auth` |

## Verification Checklist Before Installing

```pseudocode
// Before installing any AI-suggested package:

FUNCTION safe_install_package(package_name):
    // 1. Verify it exists on official registry
    IF NOT package_exists(package_name):
        THROW Error("Package does not exist: " + package_name)
    END IF

    // 2. Check package statistics
    stats = get_package_stats(package_name)

    IF stats.age_days < 30:
        prompt_user("WARNING: Package created less than 30 days ago")
    END IF

    IF stats.downloads_weekly < 100:
        prompt_user("WARNING: Package has very few downloads")
    END IF

    // 3. Review package source/repository
    IF stats.repository IS NULL:
        prompt_user("WARNING: No source repository linked")
    END IF

    // 4. Check for security advisories
    advisories = check_security_advisories(package_name)
    IF advisories.length > 0:
        prompt_user("WARNING: Security advisories exist")
    END IF

    // 5. Use lockfiles to pin versions
    install_with_lockfile(package_name)
END FUNCTION
```

## Detection Tools

| Tool | Purpose |
|------|---------|
| `npm audit` | Check npm packages for vulnerabilities |
| `pip-audit` | Audit Python packages |
| `socket.dev` | Supply chain security analysis |
| `snyk` | Vulnerability scanning |

## Detection

- Search for imports of packages that return 404 on registries
- Review AI-generated code for unusual package names
- Check if suggested packages have very few downloads
- Compare package names against known legitimate packages

## Prevention Checklist

- [ ] Always verify packages exist on official registries before installing
- [ ] Check package download counts and creation dates
- [ ] Review package source code or repository
- [ ] Use lockfiles (package-lock.json, Pipfile.lock, yarn.lock)
- [ ] Configure private registries or approved package lists
- [ ] Enable dependency scanning in CI/CD pipeline
- [ ] Don't blindly trust AI-suggested package names

## Related Patterns

- [missing-input-validation](../missing-input-validation/) - Trust but verify principle

## References

- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
- [CWE-1357: Reliance on Unverified Package](https://cwe.mitre.org/data/definitions/1357.html)
- [USENIX Study on Package Hallucination](https://arxiv.org/abs/2406.10279)
- [Socket.dev: AI Package Hallucinations](https://socket.dev/blog/ai-package-hallucinations)
