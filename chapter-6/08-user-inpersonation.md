# User Impersonation Functionality

Some applications allow privileged users (e.g., helpdesk operators or administrators) to impersonate other users for support or auditing. While useful, this functionality is often insecure and prone to exploitation, especially if improperly implemented or lacking adequate controls.

---

## Common Implementation Flaws

### 1. Unprotected or Hidden Endpoints
- Impersonation may be implemented as a **hidden feature** not protected by access controls.
- Example:  
  A URL like `/admin/ImpersonateUser.jsp` can be accessed without privilege checks.
- If discovered, attackers can impersonate arbitrary users.

### 2. Trusting User-Controlled Data
- The application may use **client-supplied values** (e.g., cookies or parameters) to determine the impersonated user.
- Example:  
  A cookie like `ImpersonatedUser=john` may be accepted without verification.
- Attackers can **modify** this data to impersonate other users without credentials.

### 3. Vertical Privilege Escalation
- If administrators can be impersonated, attackers may **escalate privileges** to gain full control over the application.
- Exploiting impersonation flaws may allow:
  - Data access
  - Configuration changes
  - Full administrative takeover

### 4. Backdoor Passwords
- Some systems use **shared override credentials** (backdoor passwords).
- These may:
  - Bypass authentication for any user
  - Be discovered during brute-force attacks
- If matched **before** the real password, they are easily detectable.
- Attackers can use such passwords to **impersonate any user**.

---

## HACK STEPS

1. **Identify impersonation features**
   - Look for impersonation links or forms in the UI.
   - Use content discovery to find hidden endpoints (e.g., `/impersonate`, `/switchUser`, etc.).

2. **Attempt direct impersonation**
   - If an impersonation feature is found, attempt to impersonate:
     - Arbitrary users
     - Known usernames
     - Guessed usernames

3. **Manipulate client-side user identity fields**
   - Review all user-submitted data:
     - Cookies
     - Parameters
     - Headers
   - Look for fields like `currentUser`, `actingAs`, `accountId`, etc.
   - Try replacing values with another user’s identifier.

4. **Try impersonating administrators**
   - If impersonation succeeds for regular users, attempt to impersonate high-privilege accounts.
   - Look for signs of escalated access (admin panels, configuration options).

5. **Watch for signs of backdoor passwords**
   - During brute-force attacks, look for:
     - Passwords that work for **multiple accounts**
     - **More than one password** working for the same account
   - Log in with suspected shared passwords and verify behavior or session indicators (e.g., “Logged in as X”).

---

## TIP

Pay attention to **non-login areas** where the application might process user identifiers or switch contexts:
- Some apps include impersonation toggles via headers, hidden fields, or query parameters.
- These can often be manipulated by replaying or modifying intercepted requests.
- If impersonation relies on a **trusted but modifiable value**, it is highly likely to be exploitable.

---

## Summary Table

| Vulnerability Type             | Description                                                                 |
|-------------------------------|-----------------------------------------------------------------------------|
| Hidden impersonation endpoint | No access controls; attackers can reach the impersonation feature directly |
| Cookie/header-based context   | Trusting user-supplied identity tokens leads to unauthorized impersonation |
| Privilege escalation          | Allows impersonation of admins, not just ordinary users                     |
| Backdoor passwords            | Shared passwords work across accounts; detected during brute-force attacks |
