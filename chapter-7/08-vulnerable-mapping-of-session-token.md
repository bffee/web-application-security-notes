# Vulnerable Mapping of Tokens to Sessions

Even if session tokens are secure and unpredictable, an application may still be vulnerable due to **flaws in how tokens are mapped to user sessions**. These flaws undermine the session management mechanism itself.

---

## Common Vulnerabilities

### 1. **Concurrent Sessions**
- Some applications allow **multiple active tokens per user**.
- Legitimate reasons (e.g. moving devices) are rare and usually short-lived.
- But concurrent sessions make it easy for:
  - Users to share accounts without restriction.
  - Attackers to use stolen credentials without detection.

> **Why it’s risky**: Users can persist in insecure practices, and attackers can remain hidden.

---

### 2. **Static Tokens**
- The application **assigns a fixed token per user**, reissuing it every login.
- This token is **always accepted**, regardless of actual login status.

> Common misuse: Poorly designed "Remember Me" implementations using static tokens in persistent cookies.

**Risks**:
- If tokens are predictable, **accounts are permanently compromised**.
- No session lifecycle exists—**authentication state is decoupled from session creation**.

---

### 3. **Per-Request Identity Binding**
- Application assigns a token (e.g., Base64 encoded `user=username;r1=random_number`) and uses it for session processing.
- Instead of treating the token as the **sole representation of identity**, the app:
  - Extracts the `user` and `r1` fields **on each request**.
  - Applies access controls based on these values directly.

> **Effectively**: The session is not a secure container; identity is derived from **client-supplied values** on every request.

**Security issue**: 
- This creates a form of **Access Control Vulnerability**—a user can forge session context by crafting valid-looking tokens with altered user fields.

---

## HACK STEPS

1. **Check for Concurrent Sessions**
   - Log in twice with the same account from different browsers/systems.
   - Observe if **both sessions remain valid** simultaneously.
   - If yes, attacker can **use stolen credentials** undetected.

2. **Check for Static Tokens**
   - Log in/out multiple times.
   - Observe if a **new session token is issued** each time.
   - If the **same token is reused**, it's not a proper session mechanism.

3. **Analyze Token Structure**
   - Look for user identifiers (e.g., username, user ID) in tokens.
   - Modify these values to refer to **other known users**.
   - If the server accepts the modified token and allows access under that identity, it's a **critical design flaw**.

---

## TIP
A session token should represent a secure, **server-side stateful context**. Identity and access control **must not depend on user-supplied fields** within the token.

---

## Summary Table

| Vulnerability Type     | Description                                                   | Impact                                       |
|------------------------|---------------------------------------------------------------|----------------------------------------------|
| Concurrent Sessions    | Multiple tokens per user accepted simultaneously              | Undetected session hijacking                 |
| Static Tokens          | Same token reused across logins                               | Permanent compromise with predictable token  |
| Identity in Token Data | Access control decisions based on token content (e.g., user)  | Identity spoofing, bypassing authentication  |
