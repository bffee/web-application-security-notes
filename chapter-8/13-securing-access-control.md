# Securing Access Controls

Access control is conceptually simple but must be implemented with **precision and discipline**. Many vulnerabilities arise from flawed assumptions about how users interact with the application and what requests need to be restricted.

---

## Common Mistakes to Avoid

Avoid relying on assumptions or insecure methods when implementing access control:

- **Do not rely on obscurity.**
  - Never assume users won’t discover URLs or resource identifiers.
  - Treat all URLs and IDs as known — enforce access through strict server-side controls.

- **Never trust user-submitted access flags.**
  - Avoid using query parameters like `?admin=true` or hidden fields to signify privilege.

- **Do not assume intended navigation flow.**
  - Just because a user can’t access a “Users” page doesn't mean they can't visit `EditUser?id=3` directly.

- **Avoid trusting any data from the client.**
  - If validated data is passed back via the client (e.g., in hidden fields), **revalidate it on the server** before use.

---

## Best Practices for Implementing Access Controls

Follow these guidelines to design effective and robust access control mechanisms:

1. **Explicitly define access requirements**
   - For each unit of functionality, define who can access it and which resources they may interact with.

2. **Session-based authorization**
   - All access decisions must be made **based on the current authenticated session**.

3. **Centralize access control logic**
   - Use a **dedicated component** to enforce access control rules.
   - All client requests must be validated through this component before access is granted.

4. **Enforce uniform access enforcement**
   - Ensure every page implements a **common access control interface**.
   - No page should be allowed to handle a request without explicit access checks.

5. **Add network-layer restrictions for sensitive features**
   - Restrict administrative functions to trusted IP ranges in addition to login-based restrictions.

6. **Secure access to static files**
   - Use either:
     - **Dynamic wrappers** that enforce access control before serving static files.
     - **Web server mechanisms** like HTTP Basic Auth to restrict access based on user/session.

7. **Never trust client-transmitted identifiers**
   - Validate all document IDs, account numbers, or any other resource specifiers on the server.

8. **Use additional safeguards for high-value actions**
   - Require **per-transaction reauthentication** and/or **dual authorization** for critical actions (e.g., fund transfers).

9. **Log sensitive operations**
   - Track and log all events involving sensitive data access or operations. Logs help with incident investigation and anomaly detection.

---

## Why Centralized Access Control Is Superior

Developers often adopt a **piecemeal approach**, adding access checks manually into each page or controller. This leads to:

- Inconsistent enforcement
- Duplicated or outdated logic
- Easier-to-miss vulnerabilities

Instead, centralized access control offers:

- **Clarity**: Access logic is consistent and easier to understand.
- **Maintainability**: Changes are applied in one place and apply everywhere.
- **Adaptability**: New policies can be implemented quickly and uniformly.
- **Reduced risk of errors**: Avoids the chance of missing access checks on new or updated pages.

---

## Summary

| **Key Principle**                        | **Recommendation**                                                |
|-----------------------------------------|-------------------------------------------------------------------|
| Resource URLs are not secrets            | Enforce access on the server side                                 |
| Don't trust client input or parameters  | Revalidate all data server-side                                   |
| Control access uniformly                 | Use a central authorization component                             |
| Protect static content                  | Use indirect access or server controls                            |
| Secure sensitive operations             | Apply reauthentication and/or dual authorization                 |
| Maintain auditability                   | Log all access to sensitive actions or data                       |

---
