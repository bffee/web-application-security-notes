# Validate Credentials Properly

Credential validation is not just about correctness but also about securely handling unexpected conditions, minimizing logic flaws, and ensuring that no attack surface is introduced through implementation mistakes.

## Password Validation

- Perform **full, case-sensitive validation** of passwords.
- Do **not modify, filter, or truncate** submitted passwords.

---

## Defensive Login Handling

- Defend against unexpected behavior using **catch-all exception handlers** during login processing.
  - On any error, **delete all session and local method data**.
  - **Invalidate the session** immediately to enforce logout, even if authentication was bypassed.

> **TIP:** Always clean up session state defensively. Don’t assume partial login failures are harmless.

---

## Code Review of Authentication Logic

- Conduct **rigorous code reviews** of authentication routines:
  - Review both **pseudocode** and **actual application source code**.
  - Look specifically for **logic errors** such as **fail-open conditions** or unexpected bypasses.

---

## User Impersonation Controls

- If the application supports **user impersonation**:
  - Restrict it to **internal administrative interfaces** only.
  - Ensure that impersonation is **tightly audited and access-controlled**.

---

## Multistage Login Processes

Multistage login flows must be implemented securely to prevent manipulation or logic abuse.

### Best Practices for Multistage Authentication:

- **Server-side state tracking** only:
  - Track all progress and prior validation **within the server-side session**.
  - Do not pass intermediate state or data back to the client.

- **Avoid resubmission of user input**:
  - Data like usernames should be collected once and stored server-side.
  - Prevent users from altering already-submitted values.

- **Stage integrity enforcement**:
  - Each stage should verify that **all previous stages were successfully completed**.
  - Otherwise, reject the authentication attempt immediately.

- **Obfuscate failure points**:
  - Always proceed through all stages, even if early validation failed.
  - Only present a **generic “login failed”** message at the end.

> **TIP:** Avoid revealing whether a username is valid by leaking information through which stage failed.

---

## Handling Randomly Varying Challenge Questions

Random challenge questions can strengthen authentication, but they must be carefully implemented.

### Secure Design Requirements:

- Use a **multistage process**:
  - Identify the user first, then present the random challenge.
- Once a user is assigned a challenge, **store it in their user profile** and reuse it on subsequent attempts until answered correctly.
- Store the current question in a **server-side session variable**, not in a hidden form field.
- **Validate** the user's answer against the stored question.

---

## Username Enumeration via Challenge Behavior

### Example Attack:

- For **valid usernames**, the same challenge question is shown repeatedly.
- For **invalid usernames**, a new question is generated each time.
- This discrepancy allows an attacker to script a **username harvesting attack**.

### Mitigation Strategy:

- For unknown usernames, store and re-use the presented question as if the user were valid.
- Periodically change the question even for invalid users to simulate a real user behavior.

> **NOTE:** Preventing all forms of username enumeration through challenge question behavior is **extremely difficult**. At some point, developers must accept that complete prevention may not be achievable against a highly determined attacker.

---

# Summary Table

| Topic                            | Best Practice                                                                 |
|----------------------------------|-------------------------------------------------------------------------------|
| Password Validation              | Validate case-sensitively without modifying or truncating                     |
| Error Handling                   | Use catch-all handlers; clear sensitive state and invalidate sessions         |
| Code Quality                     | Review authentication code carefully for logic flaws and bypasses            |
| Impersonation                    | Restrict to admins; enforce logging and access control                        |
| Multistage Login                 | Use server-side session for state; verify stage integrity; generic failures   |
| Challenge Question Handling      | Store per-user; validate server-side; prevent enumeration through reuse       |
| Enumeration Mitigation           | Simulate behavior for invalid usernames; consider rotating fake challenges    |
