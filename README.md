<p align="center" width="100%">
    <img width="50%" src="grimbard.png" alt="grimbard logo" title="grimbard logo">
</p>

# grimbard
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)

A repository of security related skills - like secure code review and pentesting - for Claude and other AI.

These skills have been proven usefull in my day to day activities as pentester and secure code reviewer. They are currentyl being tested and made better in my [baldwin.sh](https://github.com/igbuend/baldwin.sh) code reviewer environment.

## Installation

Just do:

```bash
npm install -g add-skill
npx add-skill igbuend/grimbard
```
## Skills

### SARIF Issue Reporter (SIR)

Many static analyser tools create output in the Static Analysis Results Interchange Format ([SARIF](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)) format. This skill reviews all issues and create a detailed report if the SARIF finding is valid.

> SIR is pre-alpha. Use at your own peril! Active testing ongoing.

### Security Patterns

Included are several security pattern skills covering authentication, authorization, cryptography, data protection, and system security. Each skill provides the AI with specialized knowledge to help you implement or review security best practices in your apps.

As a pentester and code reviewer I often have to explain issues at a slightly higher level than just the code. These skills are helpfull.

> The security patterns were automatically created by Claude Opus with very little review. Use at your own peril! Expect lots of improvements in the near future.

### Security Anti-Patterns

Security anti-patterns that human or AI-generated code commonly exhibits. Each skill provides BAD (vulnerable) and GOOD (secure) pseudocode patterns to help identify and fix security vulnerabilities.

## Frequently Asked Questions (FAQ)

### Why the name **grimbard**?

Grimbard is a character in the medieval fable of [**Reynard the Fox**](https://en.wikipedia.org/wiki/Reynard_the_Fox). It is a gruesome story, describing the unspeakable atrocities of the trickster.

Oh yes, Grimbard is the badger in the story, a loyal supporter, defender and advisor of the cunning fox. Grimbard represents wisdom, counsel and trustwordy guidance. Perfect for a repository of security patterns and knowledge. Grimbard also gives the advice to the wrong person, for you to decide if this person is you or the AI. Brainz overload, need more [ko-fi](https://ko-fi.com/igbuend)!

### How do skills work?

When you ask Claude Code or another AI a security-related question, it automatically:

1. **Identifies the relevant pattern(s)** based on your question
2. **Loads the pattern knowledge** from the skill.md file
3. **Applies the pattern** to your specific context
4. **Provides implementation guidance** tailored to your codebase

### Should I implement all security patterns?

No! Implement patterns based on your:

- **Threat model**: What attacks are you defending against?
- **Compliance requirements**: PCI-DSS, HIPAA, GDPR, etc.
- **Data sensitivity**: What data needs protection?
- **Risk tolerance**: What's acceptable risk?

But a security reviewer should assess the presence, absence or relevance of each security (anti) pattern. A pentester should understand all patterns and know how to abuse them.

### Do these patterns help with compliance (PCI-DSS, HIPAA, etc.)?

Yes, these patterns implement many compliance requirements:

- **PCI-DSS**: Encryption, access control, logging, key management
- **HIPAA**: Encryption, access controls, audit logging
- **GDPR**: Data protection, encryption, access controls
- **SOC 2**: Authentication, authorization, logging, encryption

However, compliance requires more than just technical controls. Consult compliance experts.

### I found a mistake in a pattern. What should I do?

Please open a GitHub issue or submit a pull request with the correction.

### Can I suggest improvements to existing patterns?

Absolutely! Open an issue or pull request with your suggested improvements.

## Future (depends on how much coffee I can afford)

- v1.0 All skills fully tested
- v2.0 AI Agent(s) with orchestration
- v3.0 The AIs will decide by then.

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/igbuend)

## Disclaimer

No AIs were harmed during the creation of these skills.

## Licensing

The code in this project is licensed under the [MIT license](LICENSE).

The documents (e.g. markdown files) in this project are licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/).

The security pattern skills were created from [Security Pattern Catalogue - DistriNet Research](https://securitypatterns.distrinet-research.be/). The [Gitlab repo](https://gitlab.kuleuven.be/distrinet/research/security-patterns/security-pattern-catalogue) is licensed under a [Creative Commons Attribution Non Commercial Share Alike 4.0 International License](https://creativecommons.org/licenses/by-nc-sa/4.0/).

The anti-pattern skills were created from [sec-context](https://github.com/Arcanum-Sec/sec-context) by [Arcanum Security](https://arcanum-sec.com/). The repository does not contain any copyright information (which legally means it is copyrighted by default). Awaiting clarification, but consider this work a derivative (IANAL).

Some of the Claude skills are (modified) versions of the [Trail of Bits Skills Marketplace](https://github.com/trailofbits/skills). These skills are licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/).



