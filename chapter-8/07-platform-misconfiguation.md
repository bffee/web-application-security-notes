# Platform Misconfiguration

Some applications rely on **platform-level access control** (e.g., web server or application server rules) to restrict access to sensitive URLs or functionality. However, misconfigurations in these controls often result in **bypassable or ineffective protections**.

---

## How It Works

Platform-level access controls typically define **rules** based on:

- **HTTP request method** (e.g., `GET`, `POST`)
- **URL path** (e.g., `/admin/create`)
- **User role or group** (e.g., `Administrator`)

> ⚠️ These rules are meant to restrict access **before** the request reaches application code, but misconfigurations often allow attackers to bypass them.

---

## Method-Based Bypass Example

Suppose an admin-only endpoint uses `POST` to create a new user:

```
POST /admin/createUser
```

A poorly configured rule may **block `POST`**, but **allow all other methods**.

- If application code **doesn’t verify the method**, an attacker can submit:
  
  ```
  GET /admin/createUser?username=hacker&role=admin
  ```

  → This request may be processed as valid since web frameworks often **treat GET and POST parameters equivalently**.

---

## Other Bypass Techniques

### 1. **Using HEAD Requests**

- `HEAD` should behave like `GET` but without a response body.
- Some platforms use the **same handler** for both `GET` and `HEAD`.
- If an action (e.g., creating an admin) can be triggered via `GET`, then `HEAD` might also trigger it.

### 2. **Unrecognized HTTP Methods**

- Some platforms **route unknown methods** (e.g., `FOO`, `HACK`) to the default `GET` handler.
- If platform only blocks `GET` and `POST`, an attacker can send:

  ```
  FOO /admin/createUser?username=hacker
  ```

  → Platform routes to `GET` → handler executes without restriction.

---

## Key Pitfalls

- Relying on **platform controls** without validating **request method** at the application level.
- Failing to **explicitly reject unsupported or invalid HTTP methods**.
- Trusting that platform-denied methods like `GET` or `POST` cover all potential vectors.

> 🔐 Always enforce access control **within application logic**, not just at the platform layer.

---

## Summary

| Misconfiguration Type              | Risk                                                       |
|------------------------------------|-------------------------------------------------------------|
| Method-based allow/deny rules      | Attackers may submit same request via a different method   |
| HEAD method misused as GET         | Sensitive actions executed silently                        |
| Unrecognized methods fallback to GET| Bypass protection via arbitrary verbs                     |
| Application doesn’t verify method  | Request processed regardless of platform restriction       |
