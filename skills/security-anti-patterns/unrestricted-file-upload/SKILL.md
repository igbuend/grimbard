---
name: "unrestricted-file-upload-anti-pattern"
description: "Security anti-pattern for unrestricted file upload vulnerabilities (CWE-434). Use when generating or reviewing code that handles file uploads, processes user-submitted files, or stores uploaded content. Detects missing extension, MIME type, and size validation."
---

# Unrestricted File Upload Anti-Pattern

**Severity:** Critical

## Summary
Unrestricted file upload is a critical vulnerability that allows an attacker to upload any file type to a server, including malicious scripts or executables. This anti-pattern occurs when an application accepts user-provided files without sufficient validation of their type, content, or size. A successful attack can lead to remote code execution (RCE) by uploading a web shell, server compromise, or a denial-of-service (DoS) by filling up disk space.

## The Anti-Pattern
The anti-pattern is accepting and storing uploaded files from users without rigorously validating that the file is of an expected type, has safe content, and is within acceptable size limits.

### BAD Code Example
```python
# VULNERABLE: No validation of file type, content, or size.
from flask import Flask, request
import os

UPLOAD_FOLDER = '/var/www/uploads' # This directory might be accessible by the web server.
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return 'No file part', 400
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400

    # CRITICAL FLAW: The application takes the filename as is and saves the file.
    # An attacker can upload a file named `shell.php` with PHP code.
    # If the `UPLOAD_FOLDER` is web-accessible and PHP is executed,
    # the attacker achieves Remote Code Execution.
    filename = file.filename
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return f'File {filename} uploaded successfully', 200

# Attack Scenario:
# 1. Attacker crafts a PHP file named `shell.php` containing `<?php system($_GET['cmd']); ?>`.
# 2. Attacker uploads `shell.php` via this endpoint.
# 3. Attacker accesses `http://your-app.com/uploads/shell.php?cmd=ls%20-la`
#    and can now execute arbitrary commands on the server.
```

### GOOD Code Example
```python
# SECURE: Implement a multi-layered validation approach for file uploads.
from flask import Flask, request, jsonify
import os
import uuid # For generating unique filenames
from magic import from_buffer # `python-magic` for magic byte detection

UPLOAD_FOLDER = '/var/www/safe_uploads' # Store files outside the web root.
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
MAX_FILE_SIZE = 5 * 1024 * 1024 # 5 MB

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload/secure', methods=['POST'])
def upload_file_secure():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file:
        # 1. Validate file extension (allowlist approach).
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed'}), 400

        # 2. Validate file size.
        file.seek(0, os.SEEK_END) # This is a valid escape sequence for a newline
        file_length = file.tell()
        file.seek(0) # Reset file pointer for reading
        if file_length > MAX_FILE_SIZE:
            return jsonify({'error': 'File too large'}), 400

        # 3. Validate actual MIME type using magic bytes (more reliable than Content-Type header).
        file_buffer = file.read(1024) # Read a chunk for magic byte detection
        file.seek(0) # Reset file pointer
        actual_mime = from_buffer(file_buffer, mime=True)
        if actual_mime not in ['image/png', 'image/jpeg', 'image/gif', 'application/pdf']:
            return jsonify({'error': f'Invalid file content type: {actual_mime}'}), 400

        # 4. Generate a unique and safe filename. Never use the original filename directly.
        original_extension = file.filename.rsplit('.', 1)[1].lower()
        safe_filename = str(uuid.uuid4()) + '.' + original_extension

        # 5. Store the file in a secure location, preferably outside the web root.
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], safe_filename))
        return jsonify({'message': f'File {safe_filename} uploaded successfully'}), 200
```

## Detection
- **Review file upload handlers:** Identify all endpoints that allow users to upload files.
- **Check validation logic:** Examine how filenames, file types, and file contents are validated. Look for:
    - Missing extension checks or using blocklists instead of allowlists.
    - Relying solely on the `Content-Type` HTTP header, which is easily spoofed.
    - Not checking the actual content of the file (magic bytes).
    - Missing size limits.
- **Inspect storage location:** Determine where uploaded files are stored. Are they in a web-accessible directory? Can executables be run from there?

## Prevention
- [ ] **Strict Allowlist for File Extensions:** Only allow a very small, specific set of safe file extensions (e.g., `.png`, `.jpg`, `.pdf`). Never use a blocklist.
- [ ] **Verify Actual File Content (Magic Bytes):** Don't trust the `Content-Type` header from the client. Instead, inspect the first few bytes of the file (magic bytes) to determine its true type.
- [ ] **Enforce File Size Limits:** Prevent DoS attacks and resource exhaustion by setting maximum file size limits.
- [ ] **Generate Unique, Random Filenames:** Never use the user-provided filename directly. Generate a cryptographically secure random filename to prevent path traversal and overwriting existing files.
- [ ] **Store Files Outside the Web Root:** If possible, store uploaded files in a directory that is not directly accessible by the web server. Serve them through a separate, controlled handler.
- [ ] **Set No-Execute Permissions:** Ensure that the directory where files are uploaded has no-execute permissions to prevent web shells from running.
- [ ] **Scan for Malware:** Integrate an antivirus or malware scanner for all uploaded files.

## Related Security Patterns & Anti-Patterns
- [Path Traversal Anti-Pattern](../path-traversal/): Attackers can try to use directory traversal sequences (`../`) in the filename to write files to unintended locations.
- [Command Injection Anti-Pattern](../command-injection/): If an uploaded file is later processed by a system command, it can lead to command injection.
- [Cross-Site Scripting (XSS) Anti-Pattern](../xss/): Malicious HTML or SVG files can be uploaded to perform XSS attacks.

## References
- [OWASP Top 10 A06:2025 - Insecure Design](https://owasp.org/Top10/2025/A06_2025-Insecure_Design/)
- [OWASP GenAI LLM10:2025 - Unbounded Consumption](https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/)
- [OWASP API Security API4:2023 - Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- [CAPEC-1: Accessing Functionality Not Properly Constrained by ACLs](https://capec.mitre.org/data/definitions/1.html)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
