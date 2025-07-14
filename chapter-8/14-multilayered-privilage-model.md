# A Multilayered Privilege Model

Access control must extend **beyond the web application layer**, encompassing the **application server, database, and operating system** to enforce **defense in depth**. This ensures that a failure at one layer does not result in total compromise.

---

## Why a Multilayered Model?

Implementing access control at **multiple infrastructure tiers** provides resilience. If one layer is bypassed, **subsequent layers can still mitigate** unauthorized actions.

---

## Examples of Layered Access Control

- **Application Server**
  - Restrict access to specific URL paths based on user roles.

- **Database Layer**
  - Use different database accounts per user type (e.g., read-only for low-privilege users).
  - Enforce fine-grained table-level access using privilege tables.
  
- **Operating System**
  - Run each service/component with the **least privileges required**.

- **Privilege Matrix**
  - A structured approach mapping application roles to permissions across all layers.
  - Helps design and audit privilege boundaries effectively.

---

## Access Control Models in a Multilayered Design

### 1. **Programmatic Control**
- Implemented via code logic.
- Often uses role classification or dynamic access checks based on database-stored privileges.
- Enables **fine-grained**, logic-driven access control.

### 2. **Discretionary Access Control (DAC)**
- **Closed DAC**: Access is denied unless explicitly granted.
- **Open DAC**: Access is granted unless explicitly revoked.
- Example: Admins delegating access or locking/expiring user accounts.

### 3. **Role-Based Access Control (RBAC)**
- Users are assigned roles which define their access rights.
- Provides scalability and easier permission management in large apps.

> ⚠️ **Design Tip**: 
> Balance is critical.
> - Too few roles → over-privileged users.
> - Too many roles → unmanageable complexity.

- Use **default-deny platform-level rules**, mirroring firewall policies.
  - Define explicit mappings of HTTP methods + paths to roles.
  - Final rule should deny everything not explicitly allowed.

### 4. **Declarative Control**
- Access policies are **defined outside** of the application logic.
- Examples:
  - Use separate low-privileged database accounts per user role.
  - Application server deployment descriptors for access rules.

> ✅ **Benefit**: Declarative control enforces access independently of app-layer logic.
> Even if the app is compromised, access is still constrained by backend roles/permissions.

---

## HACK STEPS

Even in well-defended apps, understanding where **each layer ends** can help identify attack vectors.

- **Application-layer checks** may be susceptible to:
  - Injection vulnerabilities.
  - Logic flaws in programmatic role checks.

- **Server-side RBAC** may be:
  - Incomplete or too coarse-grained.

- **Low-privileged OS accounts** might still access:
  - Sensitive files due to excessive read permissions.

- **Application server vulnerabilities** might let you:
  - Bypass app-layer access control, but not necessarily OS/database controls.

- **Privilege Escalation Path Example**:
  - If you can **change your role** in the database → log out/in → elevated access across all layers.

---

## Summary Table

| **Layer**            | **Access Control Technique**                              | **Notes**                                                                 |
|----------------------|------------------------------------------------------------|--------------------------------------------------------------------------|
| Web Application      | Programmatic checks, RBAC, DAC                             | Fine-grained logic, but vulnerable to coding mistakes                    |
| Application Server   | Declarative rules (e.g., URL-path restrictions)            | Useful for coarse access control, enforce with default-deny policies     |
| Database             | Per-role accounts, table-level privileges, privilege matrix| Offers defense even if app is compromised                               |
| Operating System     | Least-privilege accounts                                   | Restricts damage from compromised processes or users                    |

---

## Final Note

Even in a highly secure application, a **single weak point**, such as:
- Editable user roles,
- Exposed configuration endpoints, or
- Misconfigured privilege tables

...can lead to **complete privilege escalation**. Always test for **cross-layer inconsistencies**, not just app-layer weaknesses.

---
