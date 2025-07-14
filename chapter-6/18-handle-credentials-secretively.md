# Handle Credentials Secretively

To prevent unauthorized disclosure, credentials must be handled with extreme care throughout their lifecycle: creation, storage, and transmission.

## Secure Transmission of Credentials

- Use only **well-established cryptographic technologies** (e.g., SSL/TLS) to protect all client-server communications.
- **Avoid custom cryptographic implementations** for data in transit.
- If unauthenticated parts of the application use HTTP, ensure that the **login form itself is served over HTTPS**—not just the form submission.
- Only **POST requests** should transmit credentials. Avoid:
  - URL parameters
  - Cookies (including session cookies)
  - Including credentials in redirect parameters

> **TIP:** Transmitting credentials in URLs may result in them being stored in logs, browser history, and referer headers—leading to leakage.

---

## Secure Storage of Credentials

- Store credentials using a **strong cryptographic hash function** (e.g., SHA-256) with **salting**:
  - Each salt must be **account-specific**.
  - This defends against rainbow table attacks and hash substitution.
- Ensure that even if the database is compromised, original credential values **cannot be recovered**.

---

## Client-Side Storage and “Remember Me” Functionality

- Prefer remembering **non-secret items** like usernames.
- In low-security applications, optional "remember password" features may be offered but should:
  - Never store cleartext passwords on the client
  - Store passwords **reversibly encrypted using a server-known key**
  - Warn users about:
    - Risks from physical access
    - Risks from malware or remote compromise
- Eliminate **cross-site scripting (XSS)** vulnerabilities to protect client-side stored credentials (see Chapter 12).

---

## Password Change Functionality

- Implement a **password change** feature.
- Enforce **periodic password updates** to reduce long-term exposure.

---

## Credential Distribution and First-Time Use

- When distributing credentials for new accounts:
  - Use the **most secure out-of-band channel** available.
  - Ensure credentials are **time-limited**.
  - Force users to **change passwords at first login**.
  - Instruct users to **destroy the communication** after first use.

---

## Input Protection Against Keyloggers

- Consider using **drop-down menus** for collecting sensitive login input (e.g., single letters from a memorable word) to reduce keylogger exposure.
- Understand the **limitations**:
  - Sophisticated attackers may still capture screen content, form submissions, and mouse events.
  - Keyloggers are only one threat vector on a compromised system.

> **TIP:** Any client-side input protection should be seen as a **defense-in-depth** measure, not a primary security control.

---

# Summary Table

| Topic                         | Best Practice                                                                 |
|------------------------------|-------------------------------------------------------------------------------|
| Transmission Security        | Use SSL/TLS, avoid transmitting credentials via URLs, cookies, or redirects   |
| Storage Security             | Hash with account-specific salt (e.g., SHA-256); no recoverable formats       |
| Client-Side Credential Use   | Store only non-secrets or encrypted passwords; guard against XSS              |
| Password Management          | Provide change facility; enforce periodic updates                             |
| Initial Credential Delivery  | Use secure, time-limited channels; force password reset on first login        |
| Keylogger Mitigation         | Use drop-downs for partial input (optional); be aware of limitations          |
