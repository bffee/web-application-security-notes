# Multistage Functions

Many sensitive operations in web applications are split into **multiple stages**, each requiring different input and involving multiple client-server interactions. When access controls are only enforced at the **initial stage**, later stages can be abused if not equally protected.

---

## Common Pattern

- Multistage operations (e.g., **create user**, **funds transfer**) follow a sequence like:
  1. Access a menu or feature
  2. Select options (e.g., role, department)
  3. Submit details (e.g., name, password)
- **Initial stage** is protected (e.g., role check before showing "Add User" menu).
- **Later stages** assume the user already passed checks — **dangerous assumption**.

---

## Example: User Creation

1. User accesses `Add New User` via admin menu → access control enforced.
2. User selects department, role → minor validation or none.
3. User submits form with details → **no re-verification**.

> 🔓 If attacker directly accesses the third step's endpoint, they can **bypass prior checks** and create users, even admin ones.

---

## Example: Funds Transfer

In banking applications:
1. User selects **source account** → ownership validated.
2. User enters destination, amount → validated.
3. Final step: Confirm transfer → uses hidden form fields to carry earlier data.

> ❗ If the attacker **modifies the source account ID** in the final step, and the application doesn’t **recheck ownership**, they can transfer money from **someone else’s account**.

---

## Root Cause

- Developers assume users will follow the intended UI flow.
- Validation is **only applied once**, early in the process.
- Subsequent requests **trust hidden fields** or assume role validation already occurred.

---

## Key Exploitation Techniques

- **Skip to later stages** directly via crafted requests.
- **Modify hidden fields** or intercepted parameters.
- Use tools like Burp Suite to replay or alter final-stage requests.

---

## Summary

| Weakness                             | Risk Description                                          |
|--------------------------------------|------------------------------------------------------------|
| Incomplete access control per stage | Attackers can skip initial validation steps                |
| Reliance on hidden fields           | Trusting user-controlled data across stages                |
| No re-verification at final step     | Enables privilege escalation (e.g., fund transfers, role changes) |
