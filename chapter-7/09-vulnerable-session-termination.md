# Vulnerable Session Termination

Proper session termination is critical for:
1. **Limiting the lifespan** of a session token to reduce the attack window.
2. **Allowing users** to explicitly terminate sessions—especially important in shared or public environments.

---

## Common Weaknesses

### 1. **No or Weak Session Expiration**
- Some applications allow session tokens to remain valid **for days** after the last use.
- Even with difficult-to-exploit tokens, persistent sessions enable **wide-scale session harvesting**.
- Poor expiration allows attackers to test large token sets over time and potentially hijack sessions of past users.

---

### 2. **Ineffective or Missing Logout Functionality**

#### Common issues:
- **No logout functionality provided.**
- **Logout removes token client-side only**, but the server **still accepts** it if resubmitted.
- **Logout only triggers client-side script** (e.g., clearing cookie, redirecting), and server doesn't invalidate the session at all.

> In all cases, a stolen token remains usable **even after logout**, leaving the user exposed.

---

### 3. **Anonymous Users with Persistent Sessions**
- Some unauthenticated applications (e.g., shopping carts) allow sensitive data accumulation in sessions.
- These often lack a logout/clear function for users to terminate such sessions.

---

## HACK STEPS

1. **Test for Server-Side Expiration**
   - Log in and obtain a valid session token.
   - Let the session idle, then make a request to a protected resource.
   - If the resource loads normally, the session **has not expired**.
   - Use trial-and-error or automate using **Burp Intruder** with increasing delays to determine the expiration window.

2. **Check for Logout Function**
   - Verify that a logout option is clearly available.
   - If not, users can't terminate their sessions proactively, increasing exposure on shared systems.

3. **Verify Logout Effectiveness**
   - Log in and obtain a token.
   - Log out using the UI.
   - Attempt to use the **old token** to access protected resources (e.g., via **Burp Repeater**).
   - If the request still succeeds, logout did **not invalidate** the session server-side.

---

## TIP
Do **not** rely solely on client-side mechanisms (e.g., cookie clearing, JavaScript redirects) as indicators of logout or expiration. The **true test** is whether the **server continues to accept the token** after logout or idle time.

---

## Summary Table

| Vulnerability               | Description                                                           | Risk                                                   |
|----------------------------|------------------------------------------------------------------------|--------------------------------------------------------|
| Long session lifetime      | Tokens remain valid long after use                                     | Easier brute-force/token reuse attacks                 |
| No logout option           | Users can't terminate sessions on shared/public systems                | Persistent session hijacking risk                      |
| Logout ineffective         | Token is cleared on client but remains valid on server                 | Logout gives false sense of security                   |
| Client-only logout logic   | No server-side invalidation; session still active                      | Full session hijack remains possible                   |
| Anonymous persistent data  | Sessions build sensitive data without authentication or logout         | Session hijack leads to exposure of sensitive actions  |
