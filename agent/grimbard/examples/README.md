# Grimbard Examples

This directory contains example projects demonstrating Grimbard security reviews across different technology stacks and use cases.

## Available Examples

### 1. Node.js Express API (`nodejs-express-api/`)

**Technology Stack**: Node.js, Express, PostgreSQL
**Purpose**: Demonstrate security review of a REST API application

**Typical Findings**:
- SQL injection vulnerabilities
- Cross-Site Scripting (XSS)
- Missing authentication on sensitive endpoints
- Weak session management
- Hardcoded secrets
- Dependency vulnerabilities

**Key Files**:
- `src/routes/users.js` - User management endpoints
- `src/auth/auth.js` - Authentication logic
- `src/db/database.js` - Database queries
- `package.json` - Dependencies

**Run Security Review**:
```bash
cd nodejs-express-api
/grimbard-review .
```

**Expected Output**:
- ~20-30 findings across P0-P3 priorities
- Critical findings in SQL queries and authentication
- Dependency vulnerabilities from npm packages

---

### 2. Python Django Application (`python-django-app/`)

**Technology Stack**: Python, Django, SQLite/PostgreSQL
**Purpose**: Demonstrate full-stack web application security review

**Typical Findings**:
- CSRF token issues
- Insecure deserialization
- Weak password hashing configuration
- Template injection vulnerabilities
- Debug mode enabled in production
- Missing security headers

**Key Files**:
- `app/views.py` - View handlers
- `app/models.py` - Data models
- `app/settings.py` - Django configuration
- `requirements.txt` - Python dependencies

**Run Security Review**:
```bash
cd python-django-app
/grimbard-review .
```

**Expected Output**:
- ~25-35 findings
- Configuration issues in settings.py
- Template security concerns
- Python dependency vulnerabilities

---

### 3. Terraform Infrastructure (`terraform-infrastructure/`)

**Technology Stack**: Terraform, AWS
**Purpose**: Demonstrate Infrastructure as Code (IaC) security review

**Typical Findings**:
- Open S3 buckets
- Overly permissive security groups
- Missing encryption at rest
- Public RDS instances
- IAM roles with excessive permissions
- Unencrypted EBS volumes

**Key Files**:
- `main.tf` - Main infrastructure definition
- `s3.tf` - S3 bucket configurations
- `ec2.tf` - EC2 instances and security groups
- `rds.tf` - Database configurations
- `iam.tf` - IAM roles and policies

**Run Security Review**:
```bash
cd terraform-infrastructure
/grimbard-review .
```

**Expected Output**:
- ~15-25 IaC findings
- KICS findings for AWS misconfigurations
- Infrastructure security best practices violations

---

## Quick Start

### Running an Example

1. **Navigate to example directory**:
   ```bash
   cd examples/nodejs-express-api
   ```

2. **Run complete security review**:
   ```bash
   /grimbard-review .
   ```

3. **Review outputs**:
   ```bash
   cd security-review-output
   cat reports/executive-summary.md
   cat reports/technical-findings.md
   ```

### Using Examples for Testing

Examples are designed to contain intentional vulnerabilities for testing:

```bash
# Test specific workflow
/grimbard-quick examples/nodejs-express-api

# Test triage workflow
/grimbard-triage examples/nodejs-express-api/security-review-output/sarif

# Test compliance workflow
/grimbard-compliance examples/python-django-app
```

---

## Example Structure

Each example follows this structure:

```
example-name/
├── README.md                      # Example-specific documentation
├── src/                           # Source code (intentionally vulnerable)
├── tests/                         # Test files
├── security-review-output/        # Pre-generated review results
│   ├── sarif/                     # SARIF files from tools
│   ├── reports/                   # Generated reports
│   │   ├── executive-summary.md
│   │   └── technical-findings.md
│   └── findings/                  # Detailed findings
│       ├── P0-critical/
│       ├── P1-high/
│       ├── P2-medium/
│       └── P3-low/
├── expected-findings.md           # Expected security findings
└── remediation-examples/          # Example fixes for vulnerabilities
```

---

## Intentional Vulnerabilities

⚠️ **WARNING**: Examples contain intentional security vulnerabilities for educational purposes.

**DO NOT**:
- Deploy these examples to production
- Use example code in real applications without fixes
- Expose these examples on public networks

**DO**:
- Use for learning and testing Grimbard
- Study the vulnerabilities and remediation examples
- Compare your findings with expected-findings.md

---

## Node.js Express API Example Details

### Vulnerabilities Included

#### 1. SQL Injection (P0 - Critical)

**File**: `src/db/queries.js:23`

**Vulnerable Code**:
```javascript
const query = `SELECT * FROM users WHERE id = ${userId}`;
db.query(query);
```

**Fix**:
```javascript
const query = 'SELECT * FROM users WHERE id = ?';
db.query(query, [userId]);
```

#### 2. Hardcoded API Key (P0 - Critical)

**File**: `src/config/keys.js:5`

**Vulnerable Code**:
```javascript
const API_KEY = 'sk_live_abcdef123456';
```

**Fix**:
```javascript
const API_KEY = process.env.API_KEY;
if (!API_KEY) throw new Error('API_KEY environment variable required');
```

#### 3. Missing Authentication (P1 - High)

**File**: `src/routes/admin.js:10`

**Vulnerable Code**:
```javascript
router.delete('/users/:id', deleteUser);  // No auth middleware
```

**Fix**:
```javascript
router.delete('/users/:id', requireAuth, requireAdmin, deleteUser);
```

#### 4. XSS Vulnerability (P1 - High)

**File**: `src/routes/comments.js:15`

**Vulnerable Code**:
```javascript
res.send(`<div>${userComment}</div>`);  // Unsanitized user input
```

**Fix**:
```javascript
const sanitizedComment = DOMPurify.sanitize(userComment);
res.send(`<div>${sanitizedComment}</div>`);
```

### Expected Tool Results

| Tool | Expected Findings | Key Detections |
|------|-------------------|----------------|
| Opengrep | 15-20 | SQL injection, XSS, auth issues |
| Gitleaks | 3-5 | Hardcoded API keys, tokens |
| OSV-Scanner | 5-10 | Dependency vulnerabilities |
| Noir | 8-12 | API endpoints discovered |

---

## Python Django Example Details

### Vulnerabilities Included

#### 1. Insecure Deserialization (P0 - Critical)

**File**: `app/views.py:45`

**Vulnerable Code**:
```python
import pickle
data = pickle.loads(request.body)  # Dangerous!
```

**Fix**:
```python
import json
data = json.loads(request.body)
# Add schema validation
schema.validate(data)
```

#### 2. Debug Mode in Production (P1 - High)

**File**: `app/settings.py:10`

**Vulnerable Code**:
```python
DEBUG = True  # Should be False in production
```

**Fix**:
```python
DEBUG = os.environ.get('DEBUG', 'False') == 'True'
```

#### 3. Weak Password Hashing (P1 - High)

**File**: `app/auth.py:20`

**Vulnerable Code**:
```python
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()
```

**Fix**:
```python
from django.contrib.auth.hashers import make_password
password_hash = make_password(password)
```

### Expected Tool Results

| Tool | Expected Findings | Key Detections |
|------|-------------------|----------------|
| Opengrep | 12-18 | Deserialization, template injection |
| Gitleaks | 2-4 | Django secret key, database passwords |
| OSV-Scanner | 6-12 | Python package vulnerabilities |

---

## Terraform Example Details

### Misconfigurations Included

#### 1. Public S3 Bucket (P0 - Critical)

**File**: `s3.tf:10`

**Vulnerable Code**:
```hcl
resource "aws_s3_bucket" "data" {
  bucket = "sensitive-data"
  acl    = "public-read"  # Dangerous!
}
```

**Fix**:
```hcl
resource "aws_s3_bucket" "data" {
  bucket = "sensitive-data"
  acl    = "private"

  public_access_block {
    block_public_acls       = true
    block_public_policy     = true
    ignore_public_acls      = true
    restrict_public_buckets = true
  }
}
```

#### 2. Unencrypted EBS Volume (P1 - High)

**File**: `ec2.tf:25`

**Vulnerable Code**:
```hcl
resource "aws_ebs_volume" "data" {
  availability_zone = "us-west-2a"
  size              = 100
  # Missing encryption
}
```

**Fix**:
```hcl
resource "aws_ebs_volume" "data" {
  availability_zone = "us-west-2a"
  size              = 100
  encrypted         = true
  kms_key_id        = aws_kms_key.ebs.arn
}
```

#### 3. Overly Permissive Security Group (P1 - High)

**File**: `ec2.tf:45`

**Vulnerable Code**:
```hcl
resource "aws_security_group" "allow_all" {
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Open to internet!
  }
}
```

**Fix**:
```hcl
resource "aws_security_group" "web" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Internal only
  }
}
```

### Expected Tool Results

| Tool | Expected Findings | Key Detections |
|------|-------------------|----------------|
| KICS | 15-25 | S3, EC2, RDS misconfigurations |
| Gitleaks | 1-2 | Hardcoded AWS credentials (if any) |
| Opengrep | 5-8 | Terraform best practices violations |

---

## Learning Path

### Beginner: Understanding Findings

1. **Run quick scan on Node.js example**:
   ```bash
   /grimbard-quick examples/nodejs-express-api
   ```

2. **Review generated report**:
   ```bash
   cat security-review-output/reports/executive-summary.md
   ```

3. **Compare with expected findings**:
   ```bash
   diff expected-findings.md security-review-output/reports/technical-findings.md
   ```

### Intermediate: Customizing Workflows

1. **Modify tool configuration**:
   ```bash
   cp config/tools.yml examples/nodejs-express-api/custom-tools.yml
   # Edit custom-tools.yml
   ```

2. **Run with custom config**:
   ```bash
   GRIMBARD_CONFIG_DIR=examples/nodejs-express-api /grimbard-review .
   ```

3. **Compare results**:
   ```bash
   # Compare findings with different configurations
   ```

### Advanced: Creating Custom Rules

1. **Create custom Opengrep rules**:
   ```yaml
   # examples/custom-rules/my-rule.yml
   rules:
     - id: my-custom-sql-injection
       pattern: |
         db.query($QUERY + $INPUT)
       message: Potential SQL injection
       severity: ERROR
   ```

2. **Run with custom rules**:
   ```bash
   opengrep --config examples/custom-rules/ examples/nodejs-express-api
   ```

---

## Testing Grimbard Development

Use examples for testing Grimbard changes:

```bash
# Test new workflow
/grimbard-custom examples/nodejs-express-api

# Benchmark performance
time /grimbard-quick examples/*

# Validate SARIF output
python -m sarif_tools validate examples/*/security-review-output/sarif/*.sarif
```

---

## Contributing Examples

To contribute a new example:

1. **Create example directory**:
   ```bash
   mkdir examples/my-new-example
   cd examples/my-new-example
   ```

2. **Add vulnerable code** (intentional, documented)

3. **Document expected findings**:
   ```bash
   cat > expected-findings.md << EOF
   # Expected Security Findings

   ## P0 - Critical
   1. [Vulnerability name] - src/file.ext:line
   EOF
   ```

4. **Run security review**:
   ```bash
   /grimbard-review .
   ```

5. **Add remediation examples**:
   ```bash
   mkdir remediation-examples
   # Add fixed versions of vulnerable code
   ```

6. **Create example README.md**

7. **Submit pull request**

---

## Safety Guidelines

### DO NOT Use These Examples For

- ❌ Production deployments
- ❌ Real-world applications
- ❌ Security tool bypass testing
- ❌ Malicious purposes

### DO Use These Examples For

- ✅ Learning security review processes
- ✅ Testing Grimbard functionality
- ✅ Training security teams
- ✅ Demonstrating vulnerability patterns
- ✅ Developing remediation strategies

---

## Additional Resources

### Security Learning

- [OWASP Top 10](https://owasp.org/Top10/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [CWE Top 25](https://cwe.mitre.org/top25/)

### Tool Documentation

- [Opengrep Rules](https://semgrep.dev/explore)
- [KICS Queries](https://docs.kics.io/latest/queries/)
- [Gitleaks Rules](https://github.com/gitleaks/gitleaks#rules)

### Example Vulnerability Databases

- [OWASP WebGoat](https://github.com/WebGoat/WebGoat)
- [Damn Vulnerable Web Application](https://github.com/digininja/DVWA)
- [NodeGoat](https://github.com/OWASP/NodeGoat)

---

## Support

For questions about examples:
- **GitHub Issues**: https://github.com/igbuend/grimbard/issues
- **Discussions**: https://github.com/igbuend/grimbard/discussions
