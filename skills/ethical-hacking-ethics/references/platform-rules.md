# Bug Bounty Platform Rules and Guidelines

This document provides detailed information about rules of engagement, safe harbor policies, and disclosure guidelines for major bug bounty platforms.

## HackerOne

### Overview
HackerOne is the leading bug bounty and vulnerability disclosure platform, hosting over 2,000 programs and 1 million registered hackers [1].

### Safe Harbor Policy

HackerOne provides a "Gold Standard Safe Harbor" (GSSH) that organizations can adopt to protect researchers [2].

#### What is Safe Harbor?
A safe harbor is "a provision that offers protection from liability in certain situations, usually when certain conditions are met. In the context of security and AI research and vulnerability disclosure, it is a statement from an organization that security and AI researchers engaged in Good Faith Security Research and ethical disclosure are authorized to conduct such activity and will not be subject to legal action from that organization" [2].

#### Good Faith Security Research Definition
HackerOne defines Good Faith Security Research as:
> "Accessing a computer solely for purposes of good-faith testing, investigation, and/or correction of a security flaw or vulnerability, where such activity is carried out in a manner designed to avoid any harm to individuals or the public, and where the information derived from the activity is used primarily to promote the security or safety of the class of devices, machines, or online services to which the accessed computer belongs" [2].

#### Key Safe Harbor Elements
- Applies by default to all Good Faith Security Research
- Should not be tied to acceptance of specific terms at submission time
- Organization cannot unilaterally determine what's "not good faith"
- Safe harbor should not be removed retroactively
- Must follow best practices and standards

### Code of Conduct

HackerOne enforces a strict Code of Conduct with progressive sanctions [3]:

#### Enforcement Matrix

| Violation | 1st Offense | 2nd Offense | 3rd Offense | 4th Offense | 5th+ Offense |
|-----------|-------------|-------------|-------------|-------------|--------------|
| Unprofessional Behavior | Educational | 1st Warning | 2nd Warning | Final Warning | Temp Ban (12 mo) → Permanent |
| Service Degradation/Unsafe Testing | Educational | 1st Warning | 2nd Warning | Final Warning | Temp Ban (12 mo) → Permanent |
| Contacting Program Teams Out-of-Band | 1st Warning | 2nd Warning | Final Warning | Temp Ban (12 mo) → Permanent | |
| Reputation Farming/Duplicate Account Abuse | 1st Warning | 2nd Warning | Final Warning | Temp Ban (12 mo) → Permanent | |
| **Unauthorized Disclosure (Private Programs)** | Final Warning | Permanent Ban | | | |
| **Uncoordinated Vulnerability Disclosure** | Final Warning | Permanent Ban | | | |
| **Abusive Language/Harassment** | Final Warning | Temp Ban (12 mo) | Permanent Ban | | |
| **Extortion/Blackmail** | Permanent Ban | | | | |
| **Social Engineering** | Final Warning | Permanent Ban | | | |
| **Misuse of Intellectual Property** | Final Warning | Permanent Ban | | | |
| **Circumventing a Ban** | Permanent Ban | | | | |

### Rules of Engagement

#### Testing
- Stay within defined program scope
- Do not test assets not explicitly in scope
- Respect Boundaries rate limits and capacity constraints
- Do not cause service degradation
- Do not execute automated scanning without approval

#### Data Handling
- Do not access or exfiltrate data beyond proof of concept
- Do not store or share personal data discovered during testing
- Report data exposures immediately
- Follow data minimization principles

#### Communication Requirements
- Use HackerOne platform for all communications
- Do not contact program teams through other channels
- Respond to program questions within reasonable time
- Keep reports professional and detailed

### Disclosure Guidelines

#### HackerOne Disclosure Policy
- Follow program-specific disclosure policies
- Coordinated disclosure is the default for most programs
- Wait for program permission before public disclosure
- Programs must explicitly approve disclosure

#### Special Cases
- **Coordinated Disclosure:** Publish after mutual agreement
- **Non-Disclosure:** Never publish (per program rules)
- **Custom Disclosure:** Follow program-specific rules

### HackerOne Clear Requirements

For advanced platform access, researchers must:
- Pass background checks
- Demonstrate good standing
- Complete human-in-the-loop requirements
- Maintain clean Code of Conduct record

---

## Bugcrowd

### Overview
Bugcrowd is a leading crowdsourced security platform that connects organizations with security researchers [4].

### Disclose.io Framework

Bugcrowd uses Disclose.io to standardize safe harbor provisions [5].

#### Disclose.io Core Terms

Disclose.io provides "a collaborative, open source and vendor-agnostic project to standardize best practices for providing a safe harbor for security researchers within bug bounty and vulnerability disclosure programs" [5].

**Required elements for full safe harbor:**

1. **Scope Definition**
   - Exhaustive list of in-scope properties
   - Optional non-exhaustive list of out-of-scope properties
   - Clear authorization for good-faith testing

2. **Rewards Information**
   - Whether compensation is provided
   - Form of compensation (bounty, swag, recognition)
   - Magnitude of rewards

3. **Official Communication Channels**
   - Exhaustive list of acceptable communication methods
   - Designated channels for vulnerability reporting

4. **Disclosure Policy**
   - Conditions for third-party disclosure
   - Options: Coordinated, Discretionary, or Non-Disclosure

### Disclosure Types

#### Coordinated Disclosure (Default for Public Programs)
- Program Owner commits to allowing publication after fix
- Requires explicit permission before disclosure
- All parties agree on disclosure date and details
- Limited or full disclosure as agreed

#### Discretionary Disclosure
- Share with third parties only after explicit permission
- Requires Program Owner approval
- More restrictive than coordinated

#### Non-Disclosure (Default for On-Demand Programs)
- No public disclosure permitted at any time
- Most restrictive option
- Applies to Pen Test MAX engagements

#### Custom Disclosure
- Program-specific disclosure requirements
- Examples: Tesla's custom disclosure terms
- Check program brief for specific rules

### Safe Harbor Levels

Bugcrowd distinguishes between [6]:

- **Full Safe Harbor:** Programs meeting all Disclose.io requirements
- **Partial Safe Harbor:** Programs not meeting all requirements

Look for the safe harbor icon on program pages to identify commitment level.

### Code of Conduct

Bugcrowd expects researchers to:
- Act professionally and ethically
- Respect program scope and rules
- Report vulnerabilities through official channels
- Allow reasonable time for remediation
- Maintain confidentiality as required

### Proof of Concept Handling

Bugcrowd requires secure proof-of-concept sharing [7]:
- Do not upload videos to public sites (YouTube, Imgur)
- Use secure sharing for files exceeding 100MB
- Use password-protected services for sensitive POCs
- Keep proof-of-concept confidential until resolved

---

## Intigriti

### Overview
Intigriti is a European-based bug bounty platform focused on GDPR compliance and European market [8].

### Key Features

#### European Focus
- GDPR-compliant processes
- European-based programs
- Multi-language support
- EU jurisdiction emphasis

#### Authorization Requirements
- Clear scope definition required
- Explicit authorization before testing
- Written consent for all engagements
- Time-bound authorizations

#### Disclosure Policy
- Coordinated disclosure model
- Timeline agreed between researcher and program
- Publication after remediation
- Researcher recognition standards

### Platform Rules

- Follow program-specific scope
- Use official reporting channels
- Provide detailed vulnerability reports
- Allow reasonable remediation time
- Coordinate disclosure with Intigriti

---

## YesWeHack

### Overview
YesWeHack is a global bug bounty platform with presence in multiple regions [9].

### Key Features

#### Global Reach
- Multi-language support
- Global program portfolio
- Regional compliance focus
- Various program types

#### Program Types
- Public bug bounty programs
- Private programs
- Vulnerability disclosure programs (VDPs)
- Responsible disclosure programs

#### Authorization
- Follow program-specific authorization
- Scope clearly defined in program brief
- Written authorization for private programs
- Platform-mediated permissions

#### Disclosure Guidelines
- Varies by program type
- Coordinated disclosure encouraged
- Public disclosure after remediation
- Researcher attribution and recognition

---

## Common Platform Rules

### Universal Requirements

#### Scope Adherence
- Always test within defined scope
- Verify in-scope vs out-of-scope assets
- Ask for clarification if uncertain
- Do not test assumed in-scope assets

#### Documentation
- Keep records of all testing activities
- Document steps to reproduce vulnerabilities
- Maintain communication history
- Preserve evidence for disputes

#### Reporting Standards
- Submit through official channels only
- Include detailed reproduction steps
- Provide impact assessment
- Suggest remediation recommendations

#### Timeline Expectations
- Allow reasonable time for triage
- Follow program-specific response times
- Coordinate disclosure timing
- Be responsive to program questions

### Prohibited Activities

#### Always Prohibited
- Unauthorized access to any system
- Social engineering of employees
- Physical security testing (without specific authorization)
- Testing without any authorization
- Extortion or blackmail attempts
- Data theft beyond proof of concept
- Service disruption or denial of service

#### Often Restricted
- Automated scanning (may require permission)
- Third-party integration testing
- API testing beyond documented endpoints
- Source code access or reverse engineering
- Spear phishing or targeted attacks

### Data Handling Requirements

#### Personal Data
- Do not access personal data beyond testing needs
- Do not store or copy PII
- Report data exposures immediately
- Follow applicable privacy laws

#### Proof of Concept
- Keep POCs confidential
- Use secure sharing methods
- Do not publicize until fixed
- Follow platform-specific requirements

---

## Comparison Matrix

| Feature | HackerOne | Bugcrowd | Intigriti | YesWeHack |
|---------|-----------|----------|-----------|-----------|
| **Safe Harbor** | Gold Standard | Disclose.io | Varies | Varies |
| **Code of Conduct** | Detailed + enforcement | General + enforcement | Platform rules | Platform rules |
| **Disclosure Types** | Program-specific | Coordinated/Custom/Non | Coordinated | Varies |
| **Human-in-Loop** | Required for AI | Varies | Varies | Varies |
| **POC Sharing** | Platform-secured | Secure required | Platform-secured | Platform-secured |
| **Primary Focus** | Global/Enterprise | Global/SMB | Europe | Global |
| **GDPR Focus** | Yes | Yes | Strong | Varies |

---

## Best Practices by Platform

### HackerOne Best Practices
1. Enable two-factor authentication
2. Complete HackerOne Clear requirements
3. Follow the human-in-the-loop model
4. Use detailed report templates
5. Engage in the community responsibly

### Bugcrowd Best Practices
1. Check for Disclose.io compliance
2. Understand disclosure type before testing
3. Use secure POC sharing methods
4. Follow the Standard Disclosure Terms
5. Check program brief for specific rules

### Intigriti Best Practices
1. Ensure GDPR compliance
2. Verify authorization scope
3. Use official reporting channels
4. Follow European disclosure standards
5. Document all activities

### YesWeHack Best Practices
1. Understand program-specific rules
2. Follow disclosure guidelines
3. Use official channels
4. Maintain professional communication
5. Respect regional variations

---

## Emergency Procedures

### If You Go Out of Scope
1. Immediately stop all testing activities
2. Document what happened
3. Report to program immediately
4. Await instructions
5. Do not attempt to continue

### If You Discover a Critical Vulnerability
1. Follow standard reporting procedure
2. Mark report as critical/high priority
3. Include full details for program team
4. Await program guidance
5. Do not publicize until authorized

### If You Cause Service Disruption
1. Stop testing immediately
2. Contact program emergency channel
3. Document what happened
4. Be prepared to assist with recovery
5. Await permission to resume

### If Asked to Stop Testing
1. Immediately cease all activities
2. Do not attempt to continue or work around
3. Request written confirmation
4. Ask for clarification on reasons
5. Await further instructions

---

## References

[1] HackerOne - Bug Bounty Programs
https://www.hackerone.com/bug-bounty-programs

[2] HackerOne - Safe Harbor FAQ
https://docs.hackerone.com/en/articles/8494502-safe-harbor-faq

[3] HackerOne - Code of Conduct
https://www.hackerone.com/policies/code-of-conduct

[4] Bugcrowd - Platform Overview
https://www.bugcrowd.com/

[5] Bugcrowd Docs - Disclose.io and Safe Harbor
https://docs.bugcrowd.com/researchers/disclosure/disclose-io-and-safe-harbor/

[6] Bugcrowd Docs - Public Disclosure Policy
https://docs.bugcrowd.com/researchers/disclosure/disclosure/

[7] Bugcrowd Docs - Reporting a Bug
https://docs.bugcrowd.com/researchers/reporting-managing-submissions/reporting-a-bug

[8] Intigriti - Researcher Guide
https://www.intigriti.com/researcher-guide

[9] YesWeHack - Platform Overview
https://www.yeswehack.com/
