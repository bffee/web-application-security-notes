# Prevent Misuse of the Password Change Function

The password change function is a critical security mechanism that must be protected against both direct misuse and exploitation through other application vulnerabilities.

## General Requirements

- The password change feature **must always be implemented**, allowing:
  - Periodic password expiration (if policy requires)
  - Voluntary password changes by users

## Access Control

- The function should be accessible **only from an authenticated session**.
- Do **not accept any user identifier** (username) in the request:
  - Not through a form field
  - Not via hidden fields or cookies
- Users should not be able to attempt changing another user's password.

---

## Defense-in-Depth

- Require users to **re-enter their current password** before changing it:
  - Protects against misuse due to:
    - Session hijacking
    - Cross-site scripting (XSS)
    - Use of unattended terminals

---

## Password Confirmation and Validation

- Require the new password to be entered **twice** (i.e., "New password" and "Confirm password" fields).
- Perform this check **first**, and return an informative error if the entries do not match.

---

## Protection Against Brute-Force and Enumeration

- Reuse **main login security principles**:
  - Use a **generic error message** for all authentication failures.
  - **Temporarily suspend** the password change function after a small number of failed attempts.

---

## Out-of-Band Notification

- Send an **email or other out-of-band message** notifying the user of a password change.
- The notification **must not contain** the:
  - Old password
  - New password

> **TIP:** Out-of-band alerts help users detect account misuse quickly and can prompt prompt responses in case of unauthorized activity.

---

# Summary Table

| Topic                          | Best Practice                                                               |
|--------------------------------|------------------------------------------------------------------------------|
| Session Requirements           | Allow password changes only from authenticated sessions                     |
| No Username Input              | Do not allow specifying username via any mechanism                         |
| Re-Authentication              | Require the current password to be re-entered                               |
| Input Validation               | Double-entry of new password; validate and compare first                    |
| Brute-Force Protection         | Use generic errors; suspend function after repeated failed attempts          |
| User Notification              | Notify users via email or similar; exclude any credential information        |
