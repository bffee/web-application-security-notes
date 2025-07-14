# Prevent Misuse of the Account Recovery Function

Account recovery functions, if poorly implemented, can provide an easy entry point for attackers. Proper design is essential to balance security with usability.

## High-Security Applications

- In **high-risk environments** (e.g., online banking), recovery is typically handled **out-of-band**:
  - Users must **call support** and answer security questions.
  - New credentials or reset codes are sent via **conventional mail** to the user’s registered home address.

> **NOTE:** While this is secure, it's costly and generally unnecessary for most applications.

---

## General Best Practices for Recovery Mechanisms

- Avoid features like **password hints** — they provide more value to attackers than to legitimate users.
- Never disclose the original password or automatically log the user in after recovery.

---

## Recommended Automated Recovery Process

1. User initiates recovery via registered email.
2. The application sends a **unique, time-limited, unguessable, single-use URL** to that address.
3. Visiting the URL allows the user to set a new password.
4. After the password is changed:
   - Send a **confirmation email** notifying the user of the change.
5. **Do not invalidate** the user’s current credentials until a new password is set:
   - Prevents **denial-of-service** via repeated recovery requests.

---

## Secondary Challenge for Additional Protection

- Applications may include a **secondary challenge** before initiating recovery (e.g., security questions).

### Secure Challenge Design Guidelines:

- Use **predefined questions** set by the application during registration.
  - Avoid allowing users to define custom questions — these tend to be weak and enable **account enumeration**.
- Challenge answers must contain **sufficient entropy**.
  - Example: “First school name” is better than “favorite color.”
- Temporarily **suspend the account** after multiple failed attempts to prevent brute-force attacks.
- Never leak information through:
  - Success/failure of usernames
  - Whether the account is suspended
  - Which part of the process failed

---

## What Not to Do

- Do **not disclose** or resend forgotten passwords.
- Do **not initiate an authenticated session** immediately after a successful challenge.
- Do **not allow direct access** to the password reset function after challenge completion.

> **TIP:** Security questions are often **easier to guess** than passwords and must **not be treated as full authentication**.

---

# Summary Table

| Topic                              | Best Practice                                                                 |
|------------------------------------|-------------------------------------------------------------------------------|
| High-Security Recovery             | Use out-of-band (phone, postal mail) for critical applications                |
| Automated Recovery Process         | Use email with time-limited, unguessable reset URLs                           |
| Password Hint                      | Never use; they assist attackers more than users                              |
| Credential Validity                | Keep old credentials valid until user changes them                            |
| Secondary Challenge Design         | Use strong, app-defined questions; avoid user-defined or guessable ones       |
| Brute-Force Mitigation             | Suspend after failed challenge attempts; avoid leaking response details       |
| Post-Challenge Procedure           | Send email with reset link; do not disclose password or auto-authenticate     |
