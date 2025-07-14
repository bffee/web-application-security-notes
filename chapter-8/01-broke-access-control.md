# Attacking Access Controls

Access controls determine **what authenticated users are permitted to do** or access. Even with strong authentication and session management, broken access controls can completely compromise application security.

---

## Importance of Access Controls

- Access control is the **core mechanism** for deciding whether to allow an action or grant access to a resource.
- If access controls are broken:
  - Users may escalate privileges.
  - Sensitive functionality and data may be exposed.
- A common issue: applications implement solid authentication/session management but **fail to apply consistent access control checks** across all functions and resources.

> FACT: According to the authors’ findings, **71% of real-world web applications** tested had broken access controls.

---

## Why They're Hard to Get Right

- **Design-time decision**: Developers must define access rules for every operation, at every point, for every role.
- **Technology can't automatically enforce them** — human logic is required.
- **Every request must be checked** against the user's authorization context.

---

## Common Access Control Models

Access control mechanisms generally fall into three broad categories, based on how they limit users' actions:

---

### **Vertical Access Controls**

Vertical controls enforce **role-based access** — they differentiate between user roles based on privilege level.

- Example:
  - A normal user can access their profile and order history.
  - An admin user can manage all user accounts, view reports, and configure system settings.
- Misconfiguration: If a regular user can access the admin dashboard just by navigating to `/admin`, vertical access control is broken.

---

### **Horizontal Access Controls**

Horizontal controls enforce **object-level separation** — users with the same role can only access their own data, not others’.

- Example:
  - Alice and Bob are both regular users of a cloud storage service.
  - Alice should only be able to view/download her own files, not Bob’s.
- Misconfiguration: If changing a file ID in a URL (e.g., `/files/123`) lets Alice access Bob’s file, horizontal access control is broken.

---

### **Context-Dependent Access Controls**

These controls enforce **state-aware restrictions** — access is based not only on who the user is, but **what they’re doing and when**.

- Example:
  - In an e-commerce checkout, a user must:
    1. Add items to cart
    2. Choose shipping
    3. Confirm payment
  - The system should prevent the user from jumping directly to the payment page without selecting a shipping method.
- Misconfiguration: If someone can access `/confirm-payment` without going through the earlier steps, access control tied to application state is broken.

---

> These models often overlap in real applications. For instance, you might need to ensure both:
> - A user can only see **their own** (horizontal) account data.
> - And only **admins** can delete any account (vertical).


## Combined Models

- Real-world applications often **combine vertical and horizontal controls**.
- Example:
  - An accounts clerk can only pay small invoices for their department.
  - The finance director can **view** (but not pay) invoices across all departments.

---

## Attack Types

| Attack Type                   | Description                                                                 |
|------------------------------|-----------------------------------------------------------------------------|
| **Vertical Privilege Escalation** | Gaining access to **higher-level functions** not permitted for your role.       |
| **Horizontal Privilege Escalation** | Accessing or modifying **other users’ data/resources**.                         |
| **Business Logic Exploitation**    | Bypassing logical state (e.g., skipping payment step in a checkout process).   |

---

## Real-World Risk

- Exploiting horizontal flaws can lead to **vertical escalation**.
  - Example: Modifying another user’s password to hijack an admin account.
- Some flaws allow **unauthenticated users** to access restricted resources intended only for authenticated ones — the most severe form of access control failure.
