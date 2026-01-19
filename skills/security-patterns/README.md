# Security Patterns for Claude Code and Other AI

A comprehensive collection of software security patterns implemented as [AI skill](https://github.com/anthropics/skills)s. These patterns help developers design and implement secure systems by providing reusable solutions to common security problems.

## Overview

This repository contains 21 security pattern skills covering authentication, authorization, cryptography, data protection, and system security. Each skill provides the AI with specialized knowledge to help you implement security best practices in your applications.

## Available Security Patterns

### Authentication & Access Control
- **[authentication](authentication/)** - Core authentication pattern for verifying entity identity
- **[password-based-authentication](password-based-authentication/)** - Password-based authentication implementation
- **[opaque-token-based-authentication](opaque-token-based-authentication/)** - Opaque token authentication for stateless verification
- **[verifiable-token-basd-authentication](verifiable-token-basd-authentication/)** - Verifiable token authentication (JWT, signed tokens)
- **[authorisation](authorisation/)** - Access control and authorization patterns (RBAC/ABAC)
- **[session-based-access-control](session-based-access-control/)** - Session management and access control

### Cryptography
- **[cryptographic-action](cryptographic-action/)** - Core cryptographic operations and primitives
- **[cryptographic-key-management](cryptographic-key-management/)** - Key generation, storage, rotation, and lifecycle
- **[cryptography-as-a-service](cryptography-as-a-service/)** - Using external cryptographic services (HSM, KMS)
- **[self-managed-cryptography](self-managed-cryptography/)** - In-house cryptographic implementations
- **[encryption](encryption/)** - Encryption patterns and best practices
- **[digital-signature](digital-signature/)** - Digital signature creation and verification
- **[message-authentication-code](message-authentication-code/)** - MAC for message integrity

### Data Protection
- **[selective-encrypted-storage](selective-encrypted-storage/)** - Encrypt specific sensitive fields at rest
- **[transparent-encrypted-storage](transparent-encrypted-storage/)** - Transparent database/storage encryption
- **[selective-encrypted-transmission](selective-encrypted-transmission/)** - Encrypt sensitive data in transit
- **[encrypted-tunnel](encrypted-tunnel/)** - Secure communication channels (TLS/SSL)

### Security Controls
- **[data-validation](data-validation/)** - Input validation and sanitization
- **[output-filter](output-filter/)** - Output encoding and XSS prevention
- **[log-entity-actions](log-entity-actions/)** - Security event logging and auditing
- **[limit-request-rate](limit-request-rate/)** - Rate limiting and DoS protection

## Installation

### Prerequisites
- [Claude Code](https://github.com/anthropics/claude-code) CLI tool installed or similar for other AI
- Basic understanding of security concepts

### Setup

1. Clone this repository:
```bash
git clone https://github.com/igbuend/grimbard.git
cd patterns
```

2. Install skills individually or all at once:

```bash
# Install a specific skill
claude-code skill install ./skills/authorisation

# Or install all skills at once
for skill in skills/*/; do claude-code skill install "$skill"; done
```

3. Verify installation:
```bash
claude-code skill list
```

## Usage

Once installed, Claude Code will automatically invoke the appropriate security pattern skill when you ask security-related questions or request implementation help.

### Example Sessions

**Implementing Authorization:**
```
You: Help me implement role-based access control for my API

Claude will automatically invoke the "authorisation" skill and guide you through:
- Setting up enforcement points
- Designing RBAC policy structure
- Implementing decision logic
- Preventing IDOR vulnerabilities
```

**Setting Up Encryption:**
```
You: I need to encrypt user PII in the database

Claude will invoke relevant skills (selective-encrypted-storage, encryption,
cryptographic-key-management) and help with:
- Choosing appropriate encryption algorithms
- Managing encryption keys securely
- Implementing field-level encryption
- Key rotation strategies
```

**Security Review:**
```
You: Review my authentication implementation for security issues

Claude will use authentication and related skills to:
- Identify common authentication vulnerabilities
- Check for proper credential storage
- Verify session management
- Suggest security improvements
```

## Skill Structure

Each skill follows a consistent structure:

```
skills/[pattern-name]/
├── skill.md          # Pattern documentation and guidance
└── README.md         # Skill-specific information (optional)
```

The `skill.md` file contains:
- Pattern description and use cases
- Problem being addressed
- Core components and flow diagrams
- Implementation guidelines
- Security considerations
- Related patterns

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:
- Adding new security patterns
- Improving existing patterns
- Reporting issues
- Submitting pull requests

## Documentation

Additional documentation is available in the [docs/](docs/) folder:
- [Getting Started Guide](docs/getting-started.md)
- [Security Pattern Catalog](docs/pattern-catalog.md)
- [Best Practices](docs/best-practices.md)
- [FAQ](docs/faq.md)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Based on security patterns from [securitypatterns.distrinet-research.be](https://securitypatterns.distrinet-research.be/patterns/)
- OWASP Security Guidelines
- Community contributions and feedback

## Support

- **Issues**: [GitHub Issues](https://github.com/igbuend/grimbard/issues)

## Roadmap

- [ ] Add more authentication patterns (OAuth, SAML, WebAuthn)
- [ ] Expand cryptographic patterns
- [ ] Add secure coding patterns
- [ ] Add anti-patterns
- [ ] Add pattern visualization tools

## Related Projects

- [Claude Code](https://github.com/anthropics/claude-code) - AI-powered coding assistant
- [OWASP Security Patterns](https://owasp.org/) - Security best practices
- [Security Pattern Catalog](https://securitypatterns.distrinet-research.be/) - Academic security patterns

---

**Built with** [Claude Code](https://claude.com/claude-code) **for secure software development**
