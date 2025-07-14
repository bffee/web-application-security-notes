# Insecure Storage of Credentials

Even when the login mechanism itself appears secure, the **storage of credentials** can severely undermine overall application security. In many cases, credentials are stored insecurely on the server-side, enabling attackers to bypass authentication altogether by exploiting other vulnerabilities in the application.

---

## Common Storage Weaknesses

### Cleartext Password Storage

- Passwords are stored in the database in **plain text**.
- If an attacker accesses the database (e.g., via SQLi), they gain full access to all user accounts without needing to crack hashes.

### Unsalted Hashes with Standard Algorithms

- Passwords are stored using standard hash functions like **MD5** or **SHA-1**, but **without salting**.
- These hashes are vulnerable to **precomputed hash lookups** (rainbow tables).
- Even strong passwords may be reversed instantly using public hash databases.

> ⚠️ **Example online lookup tools**:
> - http://passcracking.com/index.php  
> - http://authsecu.com/decrypter-dechiffrer-cracker-hash-md5/script-hash-md5.php

### Reversible Encryption

- Some applications store passwords using **reversible encryption**.
- If the decryption key is hardcoded or accessible, an attacker can decrypt all stored passwords.

### Database-Level Exposure

- The application’s database account must have **read/write access** to credentials.
- Exploitable vulnerabilities like **SQL Injection**, **Command Injection**, or **Access Control Bypass** can allow attackers to extract stored credentials.

---

## TIP

If the application ever transmits a password back to the client (e.g., auto-filling a password field or sending it via email), this is a **clear sign** that credentials are not hashed securely and may be stored in **cleartext or with reversible encryption**.

---

## HACK STEPS

1. **Inspect All Authentication and User Management Features**
   - If a password is ever transmitted back to the client, assume insecure storage.

2. **Exploit Server-Side Vulnerabilities to Access the Credential Store**
   - If SQLi or similar flaws are available:
     - Query the database directly for credential records
     - Inspect table names like `users`, `accounts`, `logins`, etc.

3. **Determine Storage Method**
   a. If passwords are in cleartext → Immediate compromise.  
   b. If passwords are hashed → Look for **non-unique hash values** (e.g., multiple accounts with the same hash)  
   c. Check for **lack of salting** (identical password → identical hash)

4. **Leverage Online Hash Databases**
   - For unsalted hashes, attempt to reverse them using public lookup services.

---

## Summary Table

| Vulnerability Type         | Description                                      | Risk Level | Exploitable Via                  |
|---------------------------|--------------------------------------------------|------------|----------------------------------|
| Cleartext password storage| Passwords stored in readable form                | Critical   | SQLi, file read, insider threat  |
| Reversible encryption     | Encryption can be reversed with available keys   | High       | Key discovery or memory analysis|
| Unsalted hashing          | No random salt used; hashes reused               | High       | Rainbow table lookup             |
| Reused hash values        | Indicates default/common password usage          | Medium     | Account enumeration              |
