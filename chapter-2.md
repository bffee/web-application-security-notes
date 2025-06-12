# Chapter 2: Core Defense Mechanisms

## 🧠 Overview
This chapter explores the essential defense mechanisms web applications use to protect against the core security issue: **untrusted user input**. These mechanisms — access control, input validation, attacker detection, and administrative controls — also define the **main attack surface** of any application.

---

## Handling User Access

### 🔑 Key Points
- Access management involves:
  - **Authentication**: Verifying user identity.
  - **Session Management**: Tracking user activity.
  - **Access Control**: Authorizing user actions.
- These mechanisms are interdependent; weakness in one can compromise the entire application.

---

### Authentication
- Most apps use username/password, sometimes with 2FA, client certs, smartcards.
- Features include login, registration, password reset.
- Vulnerabilities include user enumeration, weak password policies, and login bypass.

---

### Session Management
- Tracks user interactions post-login using **session tokens**.
- Tokens are typically stored in cookies, hidden fields, or URLs.
- Key threats:
  - Predictable tokens.
  - Token leakage via logs or URLs.
  - Insecure transmission (missing HTTPS).
  - Session fixation or hijacking.

---

### Access Control
- Decides whether a user can perform an action or view data.
- Often role-based (user/admin) with fine-grained permissions.
- Common flaws:
  - Missing checks on some actions.
  - Relying on client-side enforcement.
  - Inconsistent logic across modules.

---

## Handling User Input

### 🔑 Key Points
- All user input is untrusted — vulnerable to manipulation.
- Input types: URLs, cookies, POST data, headers, etc.
- Input should be **validated** (whitelist), **sanitized** (escaped), or both.

---

### Varieties of Input
- Examples: text fields, query params, form inputs.
- Some inputs require strict validation (e.g., usernames), others allow variation (e.g., names with hyphens).

---

### Approaches to Input Handling
- **Whitelist (“Accept Known Good”)**: Best practice when feasible.
- **Sanitization**: Encode/remove harmful characters.
- Must account for encoding and data interpretation context.

---

### Boundary Validation
- Input that crosses system boundaries (e.g., database, OS) requires extra care.
- Examples: SQL injection, command injection.

---

### Multistep Validation and Canonicalization
- Issues occur when input is altered in multiple steps.
- Attacker may use double encoding or trick validation order (e.g., `%2527` decoded twice becomes `'`).

---

## Handling Attackers

### 🔑 Key Points
- Apps must expect skilled attackers and respond effectively.
- Measures include:
  - Graceful error handling.
  - Logging and audit trails.
  - Alerting and reactive defenses.

---

### Handling Errors
- Don’t reveal debug info or stack traces.
- Log unexpected behavior.
- Customize error responses to avoid information leakage.

---

### Maintaining Audit Logs
- Should record authentication events, sensitive actions, blocked access, attack signatures.
- Logs must be write-only and secure.
- Can help in post-incident forensics and attacker identification.

---

### Alerting Administrators
- Real-time alerts help contain threats early.
- Should detect:
  - Unusual traffic patterns.
  - Repeated login attempts.
  - Hidden field tampering.

---

### Reacting to Attacks
- Apps may throttle or block suspected attackers.
- Useful for deterring casual attacks and buying time during real breaches.

---

## Managing the Application

### 🔑 Key Points
- Admin functionality must be hardened:
  - Often accessible from same interface as user functions.
  - High-value target for privilege escalation.
  - Risks include XSS in admin panel, insufficient access controls, command injection.
- Needs robust authentication, isolation, and security auditing.

---

## 📌 Summary

Web applications rely on a few **core mechanisms** to defend against the risks posed by untrusted user input: user access control, input handling, attacker response, and application administration. These mechanisms not only define the **security posture** of the app but also present the **major attack surface**. Weaknesses here can lead to total compromise — unauthorized access, data theft, or even full system control. Understanding how each mechanism is designed, implemented, and potentially flawed is **essential for both attackers and defenders**.

