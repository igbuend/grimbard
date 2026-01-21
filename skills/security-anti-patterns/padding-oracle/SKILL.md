---
name: "padding-oracle-anti-pattern"
description: "Security anti-pattern for padding oracle vulnerabilities (CWE-649). Use when generating or reviewing code that decrypts CBC-mode ciphertext, handles decryption errors, or returns different errors for padding vs other failures. Detects error message oracles."
---

# Padding Oracle Anti-Pattern

**Severity:** High

## Summary

A padding oracle is a critical cryptographic vulnerability that occurs when an application, while decrypting data, leaks information about whether the padding of the encrypted message is correct or not. This is typically done through different error messages (e.g., "Invalid Padding" vs. "Decryption Failed") or timing differences. By carefully manipulating the ciphertext and observing the server's response, an attacker can use this "oracle" to decrypt the entire message, byte by byte, without ever knowing the encryption key. This completely breaks the confidentiality of the encrypted data.

## The Anti-Pattern

The anti-pattern is using a block cipher mode like CBC (Cipher Block Chaining) and, upon decryption, returning a different response to the user depending on the type of error that occurred.

### BAD Code Example

```python
# VULNERABLE: The decryption function returns different error messages.
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from flask import request

KEY = b'sixteen byte key' # Should be randomly generated and managed securely

@app.route("/decrypt")
def decrypt_data():
    encrypted_data = request.args.get('data').decode('hex')
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv))
    decryptor = cipher.decryptor()

    try:
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

        # Check padding
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(decrypted_padded) + unpadder.finalize()

        return "Decryption successful!", 200

    except ValueError as e:
        # THIS IS THE ORACLE!
        # If the padding is wrong, a `ValueError` is often raised with a message like "Invalid padding".
        # If the data is corrupt for another reason, a different error might occur or no error at all.
        if "padding" in str(e).lower():
            return "Error: Invalid padding.", 400
        else:
            return "Error: Decryption failed.", 500

# An attacker can now send modified ciphertext to this endpoint and, by observing whether they get a 400 or 500 error,
# they can deduce information about the plaintext.
```

### GOOD Code Example

```python
# SECURE: Use an Authenticated Encryption with Associated Data (AEAD) mode like GCM.
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import request

KEY = AESGCM.generate_key(bit_length=128) # Generate a secure key

def encrypt_gcm(data):
    aesgcm = AESGCM(KEY)
    nonce = os.urandom(12) # GCM uses a nonce
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext

@app.route("/decrypt/secure")
def decrypt_data_secure():
    encrypted_data = request.args.get('data').decode('hex')
    nonce = encrypted_data[:12]
    ciphertext_with_tag = encrypted_data[12:]

    aesgcm = AESGCM(KEY)

    try:
        # `decrypt` in an AEAD mode automatically verifies the integrity (authentication tag).
        # If the ciphertext has been tampered with in any way, it will fail with a single,
        # generic exception before it even gets to a padding step (as there is none).
        decrypted_data = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
        return "Decryption successful!", 200
    except InvalidTag:
        # CRITICAL: Any failure (tampering, corruption, etc.) results in a single, generic error.
        # This gives the attacker no useful information.
        return "Error: Decryption failed or data is corrupt.", 400

# If you MUST use CBC mode, you must use an "Encrypt-then-MAC" scheme, where you compute a MAC (like HMAC-SHA256)
# of the ciphertext and verify it *before* attempting decryption. If the MAC is invalid, you reject the message
# without trying to decrypt it.
```

## Detection

- **Review decryption code:** Look for any code that decrypts data using CBC mode.
- **Examine error handling:** Check the `try...except` blocks around decryption logic. Does the code catch different exceptions (e.g., `PaddingError`, `CryptoError`) and return different HTTP responses, status codes, or error messages for each?
- **Look for timing differences:** In some rare cases, the oracle can be a timing side channel, where valid padding checks take slightly longer than invalid ones. This is much harder to detect via code review.
- **Perform active testing:** Use a tool like `padbuster` to actively test an endpoint for a padding oracle vulnerability.

## Prevention

- [ ] **Use an Authenticated Encryption with Associated Data (AEAD) cipher mode.** This is the best solution. Modern modes like **AES-GCM** or **ChaCha20-Poly1305** combine encryption and authentication into a single, secure step. They are not vulnerable to padding oracle attacks.
- [ ] **If you must use CBC, you must also use a MAC (Encrypt-then-MAC).** First, encrypt the data. Second, compute a Message Authentication Code (like HMAC-SHA256) of the *ciphertext* (and IV). When decrypting, you must first verify the MAC. If the MAC is invalid, reject the data immediately and do not attempt to decrypt it.
- [ ] **Ensure all decryption errors are handled identically.** Whether the error is due to bad padding, a corrupt block, or an invalid MAC, the application must return the exact same generic error message and HTTP status code.

## Related Security Patterns & Anti-Patterns

- [Weak Encryption Anti-Pattern](../weak-encryption/): Choosing a vulnerable mode like CBC without a MAC is a common weak encryption pattern.
- [Timing Attacks Anti-Pattern](../timing-attacks/): A related side-channel attack where information is leaked through how long an operation takes.
- [Verbose Error Messages Anti-Pattern](../verbose-error-messages/): A padding oracle is a specific type of verbose error message vulnerability.

## References

- [OWASP Top 10 A04:2025 - Cryptographic Failures](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/)
- [OWASP GenAI LLM10:2025 - Unbounded Consumption](https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/)
- [CWE-649: Reliance on Obfuscation](https://cwe.mitre.org/data/definitions/649.html)
- [CAPEC-463: Padding Oracle Crypto Attack](https://capec.mitre.org/data/definitions/463.html)
- [Padding Oracle Attack (Wikipedia)](https://en.wikipedia.org/wiki/Padding_oracle_attack)
- Source: [sec-context](https://github.com/Arcanum-Sec/sec-context)
