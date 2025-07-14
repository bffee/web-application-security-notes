# Prevent Information Leakage

Authentication mechanisms should be designed to avoid disclosing any information that could aid an attacker in guessing or verifying authentication parameters.

## Uniform Failure Messaging

- Authentication systems must not reveal which specific credential (username, password, etc.) failed.
- All failed login attempts should result in a **generic error message**.
- Use a **single, centralized code path** to handle failed logins to avoid subtle inconsistencies, such as:
  - Typographical differences
  - Different HTTP status codes
  - Additional HTML markers or metadata

> **TIP:** Attackers can use minute differences in behavior or output to infer sensitive details like valid usernames.

---

## Lockout Policy and Information Disclosure

- If **account lockout** is implemented (e.g., after several failed attempts), do not disclose:
  - Whether a particular account is locked
  - How long it will remain locked
  - How many failures triggered the lockout

### Safe Practice:

- Use **browser-based tracking** (e.g., cookies or hidden fields) to detect multiple failed attempts from the same user agent.
- Show a **generic warning** like:
  > “Multiple login failures have been detected. If this continues, access may be temporarily suspended. Please try again later.”

> **NOTE:** This mechanism is only for user feedback and **should not serve as the actual enforcement mechanism**.

---

## Self-Registration and Username Enumeration

Attackers can use self-registration features to detect existing usernames. Two effective mitigation strategies are:

### 1. Auto-Generated Usernames

- Do not allow users to select their own usernames.
- Instead, generate a **unique, unpredictable username** automatically.

### 2. Email-Based Registration with Out-of-Band Notification

- Use **email addresses as usernames**.
- When the user submits an email address:
  - Show a generic message instructing them to check their email.
  - If the email is already registered, include that information in the email.
  - If not registered, send a unique, unguessable registration link.

> **TIP:** This approach ensures that the application does not reveal whether the email is already in use via the web interface—blocking enumeration unless the attacker controls the email account.

---

# Summary Table

| Topic                           | Best Practice                                                                 |
|---------------------------------|-------------------------------------------------------------------------------|
| Login Failure Responses         | Use a single, generic message for all failures; avoid revealing causes        |
| Code Path Consistency           | Centralize failure handling to eliminate side-channel leakage                 |
| Lockout Feedback                | Avoid disclosing lockout status or thresholds; respond with generic warnings |
| Self-Registration Enumeration   | Use auto-generated usernames or confirm registration via email only          |
| Email-Based Registration        | Do not expose account existence via UI; inform users privately via email     |
