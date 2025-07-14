# Attacking Session Management

Session management is a **core security component** in web applications. It ensures a consistent user identity across multiple requests and maintains interaction state. If compromised, an attacker can **bypass authentication** and impersonate other users.

---

## The Role of Sessions

### Importance of Sessions

- Sessions preserve the application's understanding of the user's identity **after authentication**.
- Attackers can abuse insecure session management to **masquerade as other users** — including admins.

### Stateless Nature of HTTP

- HTTP is inherently **stateless**, treating each request independently.
- Web applications use **sessions** to link multiple requests from the same user and track interaction state.

### Use Cases for Sessions

- **Authenticated Users**: Maintain identity after login until logout or timeout.
- **Unauthenticated Users**: Enable shopping carts, preferences, etc., even without login.

---

## Session Token Mechanism

### Session Token Basics

- Users receive a **unique session token** after authentication.
- This token is included in subsequent requests for user tracking.
- Typically transmitted using **HTTP cookies**.

#### Example:

` - Server: Set-Cookie: ASP.NET_SessionId=mza2ji454s04cwbgwb2ttj55`

` - Client: Cookie: ASP.NET_SessionId=mza2ji454s04cwbgwb2ttj55`

### Attack Objective

- **Hijack the session token** to impersonate users.
- May lead to **unauthorized access**, data leakage, and full application compromise.

---

## Off-the-Shelf vs Custom Implementations

- Most platforms (e.g., IIS, Java EE, ASP.NET) have **built-in session management** using cookies.
- Security-critical apps (e.g., online banking) may use **custom or non-cookie-based mechanisms** for more control.
- Both approaches may be vulnerable depending on:
  - **Token generation** methods.
  - **Token handling** during the session life cycle.

---

## Vulnerability Categories

1. **Weaknesses in Token Generation**
   - Predictable or guessable session tokens.

2. **Weaknesses in Token Handling**
   - Token exposure, reuse, improper invalidation, etc.

---

## COMMON MYTH

> **“We use smartcards, so session hijacking isn’t a threat.”**  
> FALSE — Once authenticated, the user’s **session** carries their identity.  
> A compromised session = full compromise, regardless of authentication strength.

---

## HACK STEPS

1. **Identify Potential Session Tokens**
   - Look for all client-side data:
     - Cookies
     - URL parameters
     - Hidden form fields

2. **Don’t Assume – Prove It**
   - Tokens may not be used even if present (e.g., platform defaults not in use).
   - Applications may use **multiple tokens** for different backend components.

3. **Compare Pre/Post Authentication Traffic**
   - New items introduced after login are often **session tokens**.
   - Observe changes in cookies, URLs, or hidden fields.

4. **Confirm Token Use via Elimination**
   - Use a session-dependent page (e.g., account dashboard).
   - Remove/alter each suspect item individually using tools like **Burp Repeater**.
   - If removal breaks the session, the item is likely a token.

---

## Summary Table

| Topic                          | Description                                                           | Risk                         |
|--------------------------------|-----------------------------------------------------------------------|------------------------------|
| Stateless nature of HTTP       | No built-in mechanism to track users across requests                 | Medium                       |
| Session tokens (cookies, etc.) | Used to link requests and maintain session state                     | Essential for functionality  |
| Hijacking session              | Allows impersonation of authenticated users                          | Critical                     |
| Off-the-shelf mechanisms       | May be flawed or improperly integrated                               | High                         |
| Custom mechanisms              | Provide flexibility, but are prone to implementation mistakes        | High                         |
| Key attack vectors             | Token prediction, theft, reuse, poor invalidation                    | Critical                     |

