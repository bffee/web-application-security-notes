# Prevent Brute-Force Attacks

Authentication systems must defend against brute-force attacks across all components—not just login. This includes password reset, password change, and other challenge mechanisms.

## General Countermeasures

- All authentication challenges (e.g., login, password recovery, change password) should include defenses against automation-based brute-force attempts.
- Using **unpredictable usernames** and preventing **enumeration** makes brute-force attacks significantly harder, requiring the attacker to first discover valid usernames.

---

## Account Lockout Strategies

### Strict Lockout (e.g., Banking Applications)

- After a small number of failed attempts (e.g., 3), the account is disabled.
- Recovery requires **out-of-band actions** (e.g., calling support, answering security questions).

**Disadvantages**:
- Vulnerable to **Denial-of-Service (DoS)** if an attacker repeatedly locks out users.
- High operational cost due to recovery support.

### Temporary Lockout (Recommended for Most Applications)

- After a few failed attempts (e.g., 3), **suspend the account for a short period** (e.g., 30 minutes).
- Slows brute-force attempts without fully denying service to legitimate users.

---

## Ensuring Lockout Policy Effectiveness

- Do **not reveal** that a specific account is suspended. Instead, return a **generic failure message** after multiple failed logins.
- Do not disclose:
  - The number of allowed failed attempts
  - The length of the suspension window

**Example Message**:
> “Multiple login failures have been detected. Please try again later.”

- During suspension, **reject all login attempts outright** without checking credentials.
  - Some applications mistakenly still process login attempts, leaking subtle differences if valid credentials are used.

---

## Limitations of Per-Account Lockout

Per-account lockout does **not protect** against:
- **Password spraying**: An attacker iterates over many accounts using a common weak password (e.g., `password`).
- Example: If the suspension threshold is 5 attempts, the attacker can try 4 different passwords on every account without triggering suspension.

### Mitigations:

- Prevent **username enumeration** and prediction to increase attacker effort.
- Enforce **strong password policies** to reduce the chance of users choosing guessable passwords.

---

## CAPTCHA Controls

Adding a **CAPTCHA** to brute-force-prone endpoints helps prevent automated attacks.

### Pros:
- Discourages most automated tools.
- Casual attackers will likely move on to easier targets.

### Cons:
- Some CAPTCHA implementations have been bypassed reliably.
- CAPTCHA-solving services or public competitions can crowdsource the solution.

> **TIP:** Even partially effective CAPTCHAs can drastically reduce automated abuse.

---

## CAPTCHA Implementation Vulnerabilities

- Always inspect CAPTCHA implementations for **flaws in HTML source**.
- Examples of poor implementations:
  - CAPTCHA answer exposed in the `alt` attribute of the `<img>` tag.
  - CAPTCHA answer included in hidden form fields.

> **TIP:** If attacking an application with CAPTCHA, **always view the HTML source** to check for hidden or leaked solutions.

---

# Summary Table

| Topic                       | Best Practice                                                                 |
|-----------------------------|-------------------------------------------------------------------------------|
| General Defense             | Apply automation defenses to all auth-related functions                      |
| Username Security           | Use unpredictable usernames; prevent enumeration                            |
| Strict Lockout              | Suitable for high-security apps; use out-of-band reactivation                |
| Temporary Lockout           | Suspend account briefly after failures; avoid DoS and support overload       |
| Lockout Policy Hygiene      | Generic error messages; do not disclose suspension details                   |
| Suspension Handling         | Reject all login attempts during suspension without evaluating credentials   |
| Password Spraying Defense   | Use strong password policies; prevent mass account enumeration               |
| CAPTCHA                     | Add to sensitive endpoints; verify implementation security                   |
