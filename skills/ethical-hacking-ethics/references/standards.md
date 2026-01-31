# Accepted Security Testing Standards

This document provides detailed information about industry-accepted standards for penetration testing, security assessment, and vulnerability testing.

## PTES - Penetration Testing Execution Standard

### Overview
The Penetration Testing Execution Standard (PTES) provides "a common understanding and agreement on all major points of the assignment" between penetration testers and clients [1].

### Seven Stages of PTES

#### Stage 1: Pre-engagement Interactions
This phase establishes the engagement framework [1]:

**Key Activities:**
- Define scope and objectives
- Establish rules of engagement
- Determine testing methodology
- Set timeline and milestones
- Define communication protocols
- Establish escalation procedures

**Deliverables:**
- Rules of Engagement document
- Non-Disclosure Agreement (NDA)
- Scoping document
- Timeline and milestones
- Contact information for all parties

#### Stage 2: Intelligence Gathering
Collecting information about the target organization [1]:

**Passive Intelligence Gathering:**
- Open-source intelligence (OSINT)
- Public records and filings
- Social media analysis
- Technical DNS enumeration
- WHOIS lookups
- Certificate transparency logs

**Active Intelligence Gathering:**
- Network reconnaissance
- Port scanning and service identification
- Technology fingerprinting
- Directory enumeration
- Social engineering preparation

#### Stage 3: Threat Modeling
Analyzing potential threats and attack vectors [1]:

**Key Activities:**
- Identify assets at risk
- Document architecture and data flows
- Analyze threats and attack vectors
- Prioritize vulnerabilities based on risk
- Develop exploitation strategy

**Deliverables:**
- Threat model documentation
- Attack surface analysis
- Risk prioritization matrix
- Exploitation roadmap

#### Stage 4: Vulnerability Analysis
Identifying and validating security weaknesses [1]:

**Methods:**
- Automated vulnerability scanning
- Manual testing and analysis
- Configuration review
- Code review (if applicable)
- Architecture analysis

**Validation Steps:**
1. Confirm vulnerability exists
2. Assess exploitability
3. Determine impact
4. Document findings
5. Prioritize remediation

#### Stage 5: Exploitation
Active attack simulation within scope [1]:

**Key Considerations:**
- Stay within authorized scope
- Minimize impact on target systems
- Document all activities
- Use safe exploitation techniques
- Maintain access for post-exploitation

**Types of Exploitation:**
- Network-based attacks
- Web application attacks
- Social engineering
- Wireless attacks
- Physical security testing

#### Stage 6: Post Exploitation
Maintaining access and gathering evidence [1]:

**Objectives:**
- Determine true impact of vulnerabilities
- Document access and privileges obtained
- Gather sensitive data
- Establish persistence (if authorized)
- Demonstrate lateral movement potential
- Document findings for reporting

**Important:** All post-exploitation activities must be authorized and documented.

#### Stage 7: Reporting
Communicating findings effectively [1]:

**Report Components:**
- Executive Summary
- Scope and Methodology
- Findings (with severity ratings)
- Technical Details
- Remediation Recommendations
- Appendices (evidence, logs, etc.)

**Distribution:**
- Executive report for leadership
- Technical report for IT/security teams
- Presentation for stakeholders

---

## OWASP Testing Guide (WSTG)

### Overview
The OWASP Web Security Testing Guide (WSTG) provides "a comprehensive guide to testing the security of web applications and web services" [2].

### WSTG Structure

#### Information Gathering (WSTG-INFO)
Tests for reconnaissance and information disclosure:
- WSTG-INFO-01: Conduct search engine discovery
- WSTG-INFO-02: Fingerprint web server
- WSTG-INFO-03: Review webserver metafiles
- WSTG-INFO-04: Enumerate applications
- WSTG-INFO-05: Review webpage content
- WSTG-INFO-06: Identify application entry points
- WSTG-INFO-07: Map execution paths
- WSTG-INFO-08: Fingerprint web application framework
- WSTG-INFO-09: Fingerprint web application
- WSTG-INFO-10: Map application architecture

#### Configuration and Deployment Management (WSTG-CONF)
Tests for deployment configuration issues:
- WSTG-CONF-01: Test network configuration
- WSTG-CONF-02: Test application platform configuration
- WSTG-CONF-03: Test file extensions handling
- WSTG-CONF-04: Review old backup files
- WSTG-CONF-05: Enumerate infrastructure interfaces
- WSTG-CONF-06: Test for admin interfaces
- WSTG-CONF-07: Test for leakage of sensitive info
- WSTG-CONF-08: HTTP TRACE method enabled
- WSTG-CONF-09: Test for web scripting attacks

#### Identity Management (WSTG-IDNT)
Tests for authentication and identity:
- WSTG-IDNT-01: Test role definitions
- WSTG-IDNT-02: Test user registration process
- WSTG-IDNT-03: Test account provisioning
- WSTG-IDNT-04: Testing for account lockout
- WSTG-IDNT-05: Testing for weak password policy
- WSTG-IDNT-06: Test for sensitive information
- WSTG-IDNT-07: Test for account enumeration
- WSTG-IDNT-08: Testing for weak security questions

#### Authentication Testing (WSTG-AUTHN)
Tests for authentication mechanisms:
- WSTG-AUTHN-01: Testing for credentials transported
- WSTG-AUTHN-02: Testing for default credentials
- WSTG-AUTHN-03: Testing for weak lockout mechanism
- WSTG-AUTHN-04: Testing for bypassing authentication
- WSTG-AUTHN-05: Testing for vulnerable "remember password"
- WSTG-AUTHN-06: Testing for browser cache weakness
- WSTG-AUTHN-07: Testing for account suspension

#### Authorization Testing (WSTG-AUTHZ)
Tests for authorization mechanisms:
- WSTG-AUTHZ-01: Testing for path traversal
- WSTG-AUTHZ-02: Testing for bypassing authorization
- WSTG-AUTHZ-03: Testing for horizontal access control
- WSTG-AUTHZ-04: Testing for vertical access control

#### Session Management Testing (WSTG-SESS)
Tests for session handling:
- WSTG-SESS-01: Testing for session management
- WSTG-SESS-02: Testing for cookies attributes
- WSTG-SESS-03: Testing for session fixation
- WSTG-SESS-04: Testing for exposed session variables
- WSTG-SESS-05: Testing for cross-site request forgery
- WSTG-SESS-06: Testing for logout functionality
- WSTG-SESS-07: Test session timeout
- WSTG-SESS-08: Testing for session puzzling

#### Input Validation Testing (WSTG-INPV)
Tests for injection vulnerabilities:
- WSTG-INPV-01: Testing for reflected XSS
- WSTG-INPV-02: Testing for stored XSS
- WSTG-INPV-03: Testing for DOM-based XSS
- WSTG-INPV-04: Testing for SQL injection
- WSTG-INPV-05: Testing for LDAP injection
- WSTG-INPV-06: Testing for XML injection
- WSTG-INPV-07: Testing for SSI injection
- WSTG-INPV-08: Testing for XPath injection
- WSTG-INPV-09: Testing for IMAP/SMTP injection
- WSTG-INPV-10: Testing for code injection
- WSTG-INPV-11: Testing for command injection
- WSTG-INPV-12: Testing for buffer overflow
- WSTG-INPV-13: Testing for format string
- WSTG-INPV-14: Testing for incubating vulnerabilities
- WSTG-INPV-15: Testing for HTTP verb tampering
- WSTG-INPV-16: Testing for HTTP parameter pollution

#### Error Handling (WSTG-ERRH)
Tests for error disclosure:
- WSTG-ERRH-01: Analysis of error codes
- WSTG-ERRH-02: Analysis of stack traces

#### Cryptography (WSTG-CRYP)
Tests for cryptographic weaknesses:
- WSTG-CRYP-01: Testing for weak SSL/TLS
- WSTG-CRYP-02: Testing for padding oracle
- WSTG-CRYP-03: Testing for sensitive information
- WSTG-CRYP-04: Testing for function misuse

#### Business Logic Testing (WSTG-BUSL)
Tests for business logic vulnerabilities:
- WSTG-BUSL-01: Testing for business logic
- WSTG-BUSL-02: Testing for file upload
- WSTG-BUSL-03: Testing for race conditions
- WSTG-BUSL-04: Testing for trust boundaries
- WSTG-BUSL-05: Testing for anti-automation
- WSTG-BUSL-06: Testing for UI red teaming

#### Client-Side Testing (WSTG-CLNT)
Tests for client-side vulnerabilities:
- WSTG-CLNT-01: Testing for DOM-based XSS
- WSTG-CLNT-02: Testing for JavaScript execution
- WSTG-CLNT-03: Testing for HTML injection
- WSTG-CLNT-04: Testing for client-side URL redirect
- WSTG-CLNT-05: Testing for CSS injection
- WSTG-CLNT-06: Testing for clickjacking
- WSTG-CLNT-07: Testing for WebSocket
- WSTG-CLNT-08: Testing for web messaging
- WSTG-CLNT-09: Testing for local storage
- WSTG-CLNT-10: Testing for cross-origin resource sharing

---

## NIST SP 800-115

### Overview
NIST Special Publication 800-115 provides "technical guidance for designing, implementing, and maintaining technical information security test and examination processes and procedures" [3].

### Four Phases of Security Testing

#### Phase 1: Planning

**Key Activities:**
- Define scope and objectives
- Identify authorization boundaries
- Select testing techniques
- Document rules of engagement
- Establish communication protocols

**Deliverables:**
- Test plan
- Authorization documentation
- Rules of engagement
- Communication procedures

#### Phase 2: Analysis

**Key Activities:**
- Gather information about target
- Identify vulnerabilities
- Select testing tools
- Determine test cases
- Validate methodology

**Analysis Techniques:**
- Vulnerability scanning
- Network mapping
- Port scanning
- Service identification
- Configuration review

#### Phase 3: Execution

**Testing Techniques:**

1. **Review Techniques** (Non-intrusive)
   - Documentation review
   - Log review
   - Configuration review
   - Architecture review

2. **Targeted Testing** (Focused)
   - Network discovery
   - Network port and service identification
   - Vulnerability scanning
   - Web application testing

3. **Validation Techniques** (Exploitation)
   - Exploit validation
   - Privilege escalation
   - Data extraction
   - Persistence establishment

**Important:** Testing should minimize impact on target systems.

#### Phase 4: Reporting

**Report Components:**
- Executive summary
- Scope and methodology
- Findings (categorized by severity)
- Risk ratings
- Remediation recommendations
- Evidence documentation

**Distribution:**
- Executive-level report for leadership
- Technical report for security teams
- Detailed findings for system administrators

### Technique Selection

NIST provides guidance on selecting appropriate techniques:

| Technique | Intrusiveness | Coverage | Risk Level |
|-----------|---------------|----------|------------|
| Documentation Review | Low | Medium | Very Low |
| Network Discovery | Low | High | Low |
| Network Scanning | Low | High | Low |
| Vulnerability Scanning | Medium | High | Medium |
| Web Application Testing | Medium | High | Medium |
| Penetration Testing | High | Medium | High |

### Limitations and Considerations

NIST notes limitations of technical testing:
- Cannot identify all vulnerabilities
- May miss business logic flaws
- Can impact system availability
- Results depend on tester skill
- False positives and negatives occur

---

## OSSTMM - Open Source Security Testing Methodology Manual

### Overview
OSSTMM provides "scientifically based security testing" with standardized metrics and measurements [4].

### Core Concepts

#### Security Metrics
OSSTMM provides measurable security assessments:
- Quantitative security scores
- Risk assessment metrics
- Compliance measurements
- Security awareness metrics

#### Test Types

1. **Black Box Testing**
   - No prior knowledge of target
   - Simulates external attacker
   - Limited scope visibility

2. **White Box Testing**
   - Full knowledge of target
   - Code and architecture access
   - Comprehensive testing

3. **Gray Box Testing**
   - Partial knowledge of target
   - Simulates insider threat
   - Common in professional testing

#### Security Channels

OSSTMM tests across multiple channels:
- Human Security Channel
- Physical Security Channel
- Wireless Communications Channel
- Telecommunications Channel
- Data Networks Channel
- Mobile Devices

### Methodology Components

#### 1. Interactions
Testing includes:
- People interactions
- Automated interactions
- Physical proximity
- Remote access

#### 2. Controls
Evaluating security controls:
- Authentication controls
- Access controls
- Encryption controls
- Monitoring controls

#### 3. Metrics
Measuring security:
- Attack surface analysis
- Vulnerability assessment
- Control effectiveness
- Risk quantification

---

## Industry Certification Standards

### OSCP (Offensive Security)

#### Exam Format
- 24-hour practical exam
- Simulated network environment
- Multiple machines to compromise
- Required documentation

#### Key Requirements
- Understanding of methodology
- Documentation and reporting skills
- Exploitation techniques
- Privilege escalation
- Buffer overflow development

#### Ethical Standards
- Strict adherence to authorization
- Professional conduct
- Documentation requirements
- Scope compliance

### CEH (EC-Council)

#### Curriculum Coverage
- Legal and ethical considerations
- Footprinting and reconnaissance
- Scanning and enumeration
- System hacking
- Malware threats
- Sniffing and social engineering
- Web application attacks
- Cryptography
- Cloud computing

#### Code of Ethics
- Professional conduct
- Client confidentiality
- Legal compliance
- Competence requirements

### GPEN (GIAC/SANS)

#### Focus Areas
- Advanced penetration testing
- Exploitation techniques
- Reporting and documentation
- Legal and ethical considerations

#### Methodology
- Structured approach
- Documentation focus
- Client communication
- Remediation guidance

### CREST/CHECK (UK)

#### CREST
- Professional certification body
- Multiple certification levels
- Technical and management tracks
- Background checks required

#### CHECK
- UK government-approved scheme
- Penetration testing of government systems
- Strict authentication requirements
- Geographic restrictions

### PCI-DSS Penetration Testing

#### Requirements (Requirement 11.3)
- External and internal testing
- Segmentation verification
- Defined methodology
- Qualified personnel
- Documentation and reporting

#### Scope Considerations
- Cardholder data environment
- All system components
- Segmentation boundaries
- Third-party access points

#### Testing Frequency
- At least annually
- After significant changes
- After security incidents
- Quarterly segmentation tests

---

## Best Practices for Standards Compliance

### Choosing the Right Standard

| Scenario | Recommended Standard |
|----------|---------------------|
| Web application testing | OWASP WSTG |
| General penetration test | PTES + NIST SP 800-115 |
| Compliance-driven test | NIST SP 800-115 + PCI-DSS |
| Research/academic | OSSTMM |
| Bug bounty program | OWASP WSTG + platform rules |

### Documentation Requirements

**Always document:**
- Scope and objectives
- Testing methodology
- Tools and techniques used
- Findings and evidence
- Remediation recommendations
- Timeline and milestones

### Reporting Standards

**Executive Summary Should:**
- Be understandable to non-technical stakeholders
- Highlight critical findings
- Provide business context
- Include risk ratings
- Offer prioritized recommendations

**Technical Report Should:**
- Provide detailed findings
- Include reproduction steps
- Document evidence
- Offer specific remediation
- Reference relevant standards

---

## References

[1] PTES - Penetration Testing Execution Standard
http://www.pentest-standard.org/index.php/Main_Page

[2] OWASP Web Security Testing Guide
https://owasp.org/www-project-web-security-testing-guide/

[3] NIST SP 800-115 Technical Guide to Information Security Testing and Assessment
https://csrc.nist.gov/pubs/sp/800/115/final

[4] OSSTMM - Open Source Security Testing Methodology Manual
https://www.isecom.org/
