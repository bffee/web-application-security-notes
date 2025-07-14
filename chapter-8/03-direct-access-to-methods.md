# Direct Access to Methods

A special case of broken access control occurs when applications expose **backend methods** (often APIs) directly through URLs or parameters — allowing clients to invoke internal functionality **without proper authorization checks**.

---

## Typical Scenario

- Often arises in:
  - **Java-based applications**
  - **Browser extension components** that invoke server-side methods via stubs.
- Methods may be exposed via **Java-like naming**:
  - Examples: `getBalance`, `getCurrentUserRoles`, `isExpired`

---

## Why It's Dangerous

- **Client-side logic directly calls server methods**, bypassing:
  - Input validation
  - Authorization logic
- Developers may:
  - Unintentionally expose **more methods than intended**.
  - Use APIs that **map all methods by default**, with no filtering.

---

## Realistic Example

```
http://wahh-app.com/public/securityCheck/getCurrentUserRoles
```

- May lead to unauthorized access to role data.
- Other likely exposed methods to probe:
  - `getAllUserRoles`
  - `getAllRoles`
  - `getAllUsers`
  - `getCurrentUserPermissions`

> TIP: These method-based endpoints often follow naming patterns — fuzzing with predictable method names can reveal unprotected APIs.

---

## Key Risks

- **Overexposed APIs**: Users are granted access to an entire class/interface.
- **Assumed internal-only methods** become accessible via direct HTTP calls.
- **Bypass of business logic**: Client can skip steps enforced by the UI flow.

---

## Key Takeaway

> Even if the method name looks harmless or internal, if it is reachable via a URL and lacks access control, it becomes an **attack surface**. Relying on obscurity or default configurations is a critical mistake.

---

## Summary

| Issue Type               | Impact                                                       |
|--------------------------|---------------------------------------------------------------|
| Unfiltered method access | Unauthorized execution of internal server-side logic          |
| API default exposure     | Users may invoke sensitive functions never meant for clients  |
| Naming-based endpoints   | Allows attackers to guess and access other related methods    |
