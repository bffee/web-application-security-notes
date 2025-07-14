# Insecure Access Control Methods

Some applications use **inherently unsafe access control models**, making authorization decisions based on data that is **under user control**. These flawed models can usually be bypassed with minimal effort.

---

## Parameter-Based Access Control

- The user’s **privilege level** is determined at login and stored in a **client-side parameter**:
  - Hidden form field
  - Cookie
  - URL query string

- On every request, the application reads this parameter and grants access based on its value.

**Example:**
```
https://wahh-app.com/login/home.jsp?admin=true
```

- Any user who knows or guesses the `admin=true` parameter can **forge requests** with admin privileges.

> 🔍 This vulnerability is often discovered by:
> - Comparing requests made by low- and high-privileged users.
> - Using parameter discovery techniques (see Chapter 4).

---

## Referer-Based Access Control

- Access is granted **only if the Referer header points to a specific page** (e.g., admin dashboard).

**Example Scenario:**
- User tries to access:
  ```
  https://wahh-app.com/admin/addUser.jsp
  ```
- Application checks:
  ```
  Referer: https://wahh-app.com/admin/home.jsp
  ```

- Assumes valid access if the Referer matches — which is **flawed**, since:
  - The `Referer` header is **user-controlled**.
  - Can be **spoofed easily** using tools or custom scripts.

> ❌ Never rely on Referer headers for security decisions. They’re meant for analytics/logging — not access control.

---

## Location-Based Access Control

- Access to content or functionality is restricted based on **geographic location**, typically via:
  - IP geolocation
  - Client-side geolocation APIs (e.g., GPS)

**Common bypass techniques:**
- **VPNs** and **proxies** located in the target region.
- **Roaming-enabled mobile networks**.
- **Tampering with client-side geolocation APIs** or browser settings.

> ⚠️ These controls are only **mild deterrents** and are unsuitable for critical security use-cases.

---

## Summary

| Insecure Method             | Why It's Broken                                           |
|----------------------------|------------------------------------------------------------|
| Parameter-based roles       | User can forge their own privilege level in requests       |
| Referer-based authorization | Referer headers are client-controlled and spoofable       |
| Location-based restrictions | Easily bypassed with VPNs, proxies, or client tampering   |
