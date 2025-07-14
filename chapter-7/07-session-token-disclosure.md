# Disclosure of Tokens in Logs

Even if tokens aren't exposed via the network, **logging practices** may inadvertently leak them. These leaks can be more severe, exposing tokens to **broader audiences**—admins, developers, or even external attackers accessing logs.

---

## Token Disclosure Through Logs

### 1. **Monitoring Interfaces**
- Admin/support interfaces may display session tokens.
  - Example: A helpdesk views user sessions and sees the actual token.
- If poorly protected, these interfaces can allow **unauthorized users** to view or hijack sessions.

### 2. **Tokens in URLs**
- Some applications pass session tokens via the **URL query string** instead of cookies or POST bodies.
  - e.g. `http://example.com/page;jsessionid=ABC123`

#### Consequences:
- Tokens end up in:
  - Browser history
  - **Web server logs**
  - Corporate/ISP **proxy logs**
  - **Reverse proxy** logs (e.g., load balancers)
  - **Referer headers** (when visiting external links)

#### Example:
```http
GET /page;jsessionid=ABC123 HTTP/1.1
Referer: http://example.com/page;jsessionid=ABC123
```

---

## Referer-Based Leaks

If a user **clicks a link** or the browser loads a resource (like an image) from an off-site domain:
- The full URL (with session token) may be sent in the **Referer header**.
- Attacker-controlled servers can log and **harvest tokens in real time**.

> This is a common attack vector in **webmail applications** that include session tokens in URLs.

### Browser Behavior
- **IE**: Strips `Referer` when following off-site links from HTTPS pages.
- **Firefox**: Sends full `Referer` if both the current and off-site links are HTTPS—even across domains.

---

## HACK STEPS

1. **Identify Token Display in Monitoring UIs**
   - Search for session-management or diagnostic pages.
   - Determine access controls—admin-only? authenticated users? anonymous?

2. **Search for Token-in-URL Usage**
   - Look for session IDs passed in query strings or path.
   - Common in external system integrations or legacy apps.

3. **Exploit Off-Site Link Injection**
   - Locate places where arbitrary links can be posted (e.g., forums, comments).
   - Post links to your server and check `Referer` logs for incoming tokens.

4. **Session Hijack with Captured Tokens**
   - Intercept a response in Burp and inject the stolen session token via a `Set-Cookie` header.
   - Alternatively, configure Burp to use a specific cookie globally.

5. **Automated Harvesting (Optional)**
   - If many tokens are captured, automate session hijacking to extract:
     - User data
     - Payment info
     - Passwords
   - (See Chapter 14 for automation techniques.)

---

## TIP
**Never transmit tokens in URLs**. Always use **secure, HttpOnly cookies**, and **protect logs** from unauthorized access. Even with HTTPS, Referer-based leakage remains a risk.

---

## Summary Table

| Vector                            | Risk Description                                     |
|----------------------------------|------------------------------------------------------|
| Admin UIs with session listings  | May expose tokens if poorly secured                 |
| Tokens in URLs                   | Appear in logs and browser history                  |
| Referer leakage to external sites| Tokens sent to attacker-controlled domains          |
| Logs (proxy/server/browser)      | Wide exposure to multiple internal entities         |
| Automation risk                  | Allows mass hijacking of user sessions              |
