# Client Exposure to Token Hijacking

Attackers can exploit **client-side vulnerabilities** or weaknesses in **session token behavior** to hijack a user’s session, gaining unauthorized access to sensitive functionality or data.

---

## Common Attack Vectors

### 1. **Cross-Site Scripting (XSS)**
- A common use of XSS is to extract the victim’s **session token** via JavaScript and send it to an attacker-controlled server.
- Chapter 12 provides in-depth coverage of XSS payloads and scenarios.

### 2. **Session Fixation**
- The attacker sets or injects a **known token** into the victim’s browser before login.
- Once the victim logs in, the attacker reuses the known token to hijack the session.
- Exploits trust in a session identifier rather than user authentication.

### 3. **Cross-Site Request Forgery (CSRF/XSRF)**
- Relies on a **user being logged in** while visiting a malicious site.
- The site causes the browser to send requests **with valid session cookies**.
- The attacker can perform unauthorized actions using the **user's session context**.

---

## HACK STEPS

### **XSS-based Token Theft**
1. Identify any **reflected or stored XSS** vulnerabilities.
2. Test if injected scripts can access `document.cookie` and exfiltrate the session token to an external domain.

---

### **Session Fixation Detection**
3. If session tokens are issued **before login**, log in using an issued token and observe:
   - If the **same token persists** post-login → vulnerable to fixation.

4. Try logging in as **two different users** using the same token:
   - If the token remains unchanged and valid → fixation possible.

5. Attempt to create a **validly-structured token manually** and login with it:
   - If accepted, the session handling is **misconfigured** and vulnerable to fixation.

6. For applications without login:
   - Check if a token set during **anonymous use** remains valid to access **post-submission sensitive data**.
   - If yes, session fixation is still a valid concern.

---

### **CSRF Exploitation Testing**
7. Log in, then make a crafted request from another origin (site).
8. Confirm whether:
   - **Session cookies are auto-submitted**.
   - **Sensitive actions** (like changing email, submitting orders) can be done using **predictable parameters**.

---

## TIP
Even if tokens are strong and unpredictable, **client-side exposure (e.g., via XSS or CSRF)** can completely undermine session security.

- Always test:
  - Whether the session token changes after login.
  - If logins are accepted with attacker-defined tokens.
  - If user actions can be forced remotely via CSRF.

---

## Summary Table

| Attack Type      | Description                                                                 | Condition for Exploit                                     |
|------------------|-----------------------------------------------------------------------------|-----------------------------------------------------------|
| XSS              | Steal session tokens via `document.cookie`                                  | XSS + accessible cookie                                   |
| Session Fixation | Victim logs in with attacker-known token                                     | Token not regenerated after login                         |
| CSRF             | Forge requests using user's cookies                                          | Browser auto-submits cookies + attacker knows parameters  |
