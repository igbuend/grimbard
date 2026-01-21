---
name: "hallucinated-packages-anti-pattern"
description: "Security anti-pattern for hallucinated (non-existent) packages (CWE-1357). Use when generating or reviewing AI-assisted code that imports packages, dependencies, or libraries. CRITICAL AI-specific vulnerability with 5-21% hallucination rate. Detects dependency confusion and slopsquatting risks."
---

# Hallucinated Packages Anti-Pattern

**Severity:** Critical

## Summary
AI models, including large language models (LLMs), have a tendency to "hallucinate" and suggest installing software packages that do not exist in official repositories. Attackers exploit this by registering these non-existent package names (a technique called "slopsquatting" or "dependency confusion"). When a developer, trusting the AI's suggestion, installs the hallucinated package, they inadvertently execute malicious code from the attacker. This is a critical, AI-specific supply chain vulnerability that can lead to malware execution, credential theft, and system compromise.

## The Anti-Pattern
The anti-pattern is to blindly trust and install a package suggested by an AI model without first verifying its existence, legitimacy, and reputation.

### BAD Code Example
```python
# An AI model generates the following code snippet and instruction:
# "To handle advanced image processing, you should use the `numpy-magic` library.
# First, install it using pip:"
#
# $ pip install numpy-magic

import numpy_magic as npmagic

def process_image(image_path):
    # The developer assumes `numpy-magic` is a real, safe library.
    # However, it doesn't exist, and an attacker has registered it on PyPI.
    # The moment it was installed, the attacker's code ran.
    # The import itself could also trigger malicious code.
    processed = npmagic.enhance(image_path)
    return processed

```
In this scenario, the developer follows the AI's instructions without question. The `numpy-magic` package is not a real library. An attacker, anticipating this hallucination, has published a malicious package with that exact name. The developer's `pip install` command downloads and executes the attacker's code, compromising their machine and potentially the entire project.

### GOOD Code Example
```python
# SECURE: Verify the package before installing.

# Before installing `numpy-magic`, the developer performs a few checks.

# 1. Search for the package on the official repository (e.g., PyPI, npm).
#    A search for "numpy-magic" on PyPI yields no results or shows a package
#    with very low downloads and a recent creation date. This is a major red flag.

# 2. Look for signs of legitimacy.
#    - Does the package have a link to a GitHub repository?
#    - Is the repository active?
#    - How many weekly downloads does it have? (Is it in the single digits or thousands?)
#    - Who are the maintainers?
#    - Are there any open issues or security advisories?

# 3. Search for the *functionality* instead of the package name.
#    A search for "advanced numpy image processing" leads to well-known libraries
#    like `scikit-image`, `OpenCV (cv2)`, or `Pillow (PIL)`, which are reputable.

# The developer chooses a legitimate, well-known library instead.
from skimage import io, filters

def process_image(image_path):
    image = io.imread(image_path)
    # Use a function from a verified, reputable library.
    processed = filters.gaussian(image, sigma=1)
    return processed
```

## Detection
- **Verify Package Existence:** Before installing, search for the package on its official registry (e.g., `pypi.org`, `npmjs.com`). If it doesn't exist or was created very recently, it's a hallucination.
- **Check for Typosquatting:** Does the package name look like a typo of a more popular package (e.g., `reqeusts` instead of `requests`)?
- **Review Package Statistics:** Check the package's download count, release history, and maintainers. A brand-new package with very few downloads is highly suspicious.
- **Use Auditing Tools:** Tools like `npm audit`, `pip-audit`, and `socket.dev` can help identify known vulnerabilities and suspicious packages.

## Prevention
- [ ] **Always verify a package's existence** and reputation on its official registry before installing it.
- [ ] **Never blindly trust a package name** suggested by an AI. Treat it as a hint, not a command.
- [ ] **Check package download counts, creation dates, and maintainer reputation.**
- [ ] **Use lockfiles** (`package-lock.json`, `Pipfile.lock`, `yarn.lock`) to ensure that you are always installing the same version of a dependency.
- [ ] **Configure a private registry** or an approved list of packages for your organization to prevent developers from installing untrusted dependencies.
- [ ] **Integrate dependency scanning** and auditing tools into your CI/CD pipeline.

## Related Security Patterns & Anti-Patterns
- [Missing Input Validation Anti-Pattern](../missing-input-validation/): The core issue is a failure to validate the "input" from the AI model.

## References
- [OWASP Top 10 A03:2025 - Software Supply Chain Failures](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/)
- [OWASP GenAI LLM03:2025 - Supply Chain](https://genai.owasp.org/llmrisk/llm03-supply-chain/)
- [OWASP API Security API10:2023 - Unsafe Consumption of APIs](https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/)
- [CWE-1357: Reliance on Unverified Package](https://cwe.mitre.org/data/definitions/1357.html)
- [CAPEC-538: Open-Source Library Manipulation](https://capec.mitre.org/data/definitions/538.html)
- [USENIX Study on Package Hallucination](https://arxiv.org/abs/2406.10279)
- [Socket.dev: AI Package Hallucinations](https://socket.dev/blog/ai-package-hallucinations)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
