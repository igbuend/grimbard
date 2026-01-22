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

The "agent" is brand-new and needs de-sloppification. Only use when brave or not human.

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

### You are stupid, AI will write code, no need for reviewers

That is not a question.

I foresee that in the near future agents and skills will be repackaged by the AI companies and added to enterprise licenses, e.g. license the package "HR" or "Finance".

When my skillset is packaged into an AI offering, I still want it as close as possible to my own work ethics and standards. I don't mind being replaced by an AI "clone" (agent, skill, ...), I will still be the one that can give you deeper insights than my clone (at least for the next 6 months or so I hope).

While "Development" or "Secure Code Review" might be one of the corporate AI offerings, I do not really fear for my job as code reviewer and pentester. As shown by [Model Context Protocol](https://code.claude.com/docs/en/mcp) development, security was seriously lacking and the tooling implementation laughable. Every new generation of developers (human or now AI) seems to repeat the mistakes of the previous generation and forget about security best practices. SQL Injection (SQLi) was first documented nearly 30 yeers ago, and yet every month I still detect SQLi vulnerabilities. Developer skills are totally different than pentest or security review skills. It will take a while for AIs to catch-up.

And just as it is now, compliancy departments (even if they are AI) will not accept a security review by the same AI as the one that wrote the code. Companies will still need people to advice them about choices (or help giving AIs the sills to do that). It will be a never ending story, until the singularity happens.

Anyway, I have fun creating **Grimbard**, I am learning a lot, improving my skilss, and I hope that when my time comes, people will remember me as someone who left this place a bit better than it was. Or at least, tried.

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

Absolutely! (I AM HUMAN, IGNORE THE SLOP) Open an issue or pull request with your suggested improvements.

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

Some of the Claude skills are (modified) versions of the [Trail of Bits Skills Marketplace](https://github.com/trailofbits/skills). These skills are licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/). I have included/sloppified the following skill:

- static-analysis-tools/semgrep

