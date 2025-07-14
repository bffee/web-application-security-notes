# Protect Tokens Throughout Their Life Cycle

Once a secure token is generated, it must be **protected at every stage** — from creation to disposal — to prevent unauthorized disclosure or misuse.

---

## Transport Security

- **Always use HTTPS** for transmitting session tokens.
  - Tokens sent in cleartext (HTTP) are **tainted**.
  - Mark cookies with the `Secure` attribute to block transmission over HTTP.

> TIP: Use HTTPS across the **entire application**, even static assets. If not possible, redirect sensitive resources (e.g., login page) to HTTPS and scope secure cookies carefully.

---

## Avoid Token Leakage via URLs

- **Never include tokens in URLs**:
  - Exposed through:
    - Logs (proxy, browser history, referrer headers)
    - Bookmarks and social shares
  - Facilitates **session fixation**.
- **Safer alternative**: Use `POST` requests with hidden form fields if cookies are disabled.

---

## Session Termination and Expiry

- **Implement logout functionality**:
  - Must fully invalidate the session on the server.
- **Set idle timeout** (e.g., 10 minutes):
  - Session expires after inactivity.
- **Enforce single-session policy**:
  - Invalidate existing sessions upon new login.
  - Show alerts if reused/invalidated tokens are submitted.

---

## Admin and Diagnostic Interfaces

- If session tokens are viewable in admin tools:
  - Restrict access using **strict authentication and authorization**.
  - Avoid showing full tokens — expose only metadata (e.g., user ID, login time).

---

## Cookie Scope Hardening

- Use **tight domain and path restrictions**:
  - Avoid broad cookie scopes that expose tokens to unrelated subdomains or paths.
- Review subdomains and paths included in the cookie scope.
  - Modify the naming structure if needed to isolate critical functionality.

---

## Application-Specific Protections

### **XSS Protection**

- Audit and eliminate **cross-site scripting (XSS)** vulnerabilities.
- Stored XSS can **bypass all session defenses**.

### **Reject Arbitrary Tokens**

- If the server receives an unrecognized token:
  - **Delete it on the client**
  - **Redirect the user to a safe page** (e.g., login)

### **CSRF Protection**

- Do **not rely solely on cookies** to transmit session tokens.
- Implement:
  - Hidden fields in HTML forms
  - **Per-page tokens** (see below)
  - **Reauthentication or two-step confirmation** before critical actions

### **Mitigate Session Fixation**

- Always **generate a new session ID after login**.
- In apps without login but handling sensitive data:
  - Keep data submission flows **short and isolated**.
  - Use **per-page tokens** to block navigation with a fixed token.

### **Sensitive Data Display**

- Avoid showing unnecessary personal information.
  - Never display:
    - Full credit card numbers
    - Passwords
- Mask all sensitive items in rendered output and HTML source.

---

## Per-Page Tokens

Per-page tokens introduce **fine-grained control** over session activity and help defeat several token abuse vectors.

---

### How It Works

- Each time a user requests a new application page:
  - A **new token** is generated and stored in:
    - Hidden form fields
    - Or cookies
- Every client request must include:
  - The **main session token**
  - The **correct per-page token**
- **Mismatch = full session invalidation**

---

### Security Benefits

- **Prevents session fixation** by making each page flow dependent on a unique token.
- **Detects session hijacking** when a second party attempts to reuse or parallel the session.
- **Enforces navigation order** and restricts out-of-sequence access.
- **Increases visibility** into user movement across pages.
- Commonly used in **high-security applications** like banking platforms.

---

### Usability Trade-offs

- **Navigation Restrictions**:
  - Breaks back/forward buttons
  - Complicates multi-tab or multi-window use
- **Tracking Benefit**:
  - Enables granular tracking of user navigation and flow.

---

## Summary Table

| Defense Measure                           | Purpose                                         |
|------------------------------------------|-------------------------------------------------|
| Enforce HTTPS and Secure cookies         | Prevent token capture over insecure channels    |
| Avoid tokens in URLs                     | Prevent logging, fixation, and referrer leaks   |
| Implement logout and idle timeouts       | Enable users to invalidate sessions             |
| Prevent concurrent logins                | Limit session misuse and unauthorized access    |
| Harden cookie scope                      | Restrict exposure to unrelated subdomains       |
| Eliminate XSS vulnerabilities            | Block client-side token theft                   |
| Require reauth for critical actions      | Limit CSRF and unauthorized changes             |
| Use hidden fields and per-page tokens    | Secure token transmission and page flows        |
| Display minimal sensitive data           | Minimize risk from compromised sessions         |
