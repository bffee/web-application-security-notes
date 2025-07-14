# Liberal Cookie Scope

Session cookies should be scoped narrowly to minimize exposure to unintended or untrusted domains and paths. Misconfigured domain or path attributes can allow unrelated applications to access or leak session tokens.

---

## Cookie Domain Restrictions

### **Default Behavior**
- Cookies are resubmitted to:
  - The **origin domain** and its **subdomains**.
  - **Not** to parent domains or sibling subdomains.

### **Explicit Domain Scope**
- Using the `domain` attribute in `Set-Cookie`:
  ```http
  Set-Cookie: sessionId=abc123; domain=wahh-app.com;
  ```
  - Cookie will be sent to **wahh-app.com** and **all its subdomains**.

### **Security Implications**
- **Overly broad domain scope** can expose cookies to:
  - Less secure or untrusted subdomains.
  - Applications with XSS or logging flaws.
- Browsers **ignore**:
  - Domain attributes violating scope rules (e.g., setting cookie for `.com`).
  - But allow scoping to parent domain (e.g., `wahh-org.com` from `secure.wahh-org.com`).

---

## Real-World Examples

### **Subdomain Takeover Risk**
- Blogging app at `wahh-blogs.com`, where user blogs reside at:
  ```
  abuzark.wahh-blogs.com
  hitler.wahh-blogs.com
  ```
- If session cookie is scoped to `.wahh-blogs.com`, malicious bloggers can:
  - Use **stored XSS** to steal tokens of logged-in users who visit their blogs.

### **Parent Domain Scope**
- Sensitive app at `secure.wahh-org.com` sets:
  ```http
  Set-Cookie: sessionId=xyz; domain=wahh-org.com;
  ```
- Token gets sent to:
  - `testapp.wahh-org.com`
  - `www.wahh-org.com`
- Issues:
  - Lower-trust teams or apps may mishandle tokens.
  - XSS or insecure logging in other apps compromises all users.

### **Segregation Failure**
- **Cookies don't respect protocol or port differences**.
  - Apps at `https://app.com` and `http://app.com:8080` share cookies.

---

## Cookie Path Restrictions

### **Default Behavior**
- If app is at `/apps/secure/foo-app/`, cookie defaults to:
  - `/apps/secure/foo-app/` and **subpaths**.
  - Not sent to sibling or parent paths.

### **Custom Path Scoping**
- Server can set broader scope:
  ```http
  Set-Cookie: sessionId=abc; path=/apps/;
  ```

### **Security Considerations**
- **Path-based scoping is weak**:
  - JavaScript in sibling/parent paths can still:
    - Load iframes.
    - Access same-origin cookies.
- **Same-origin policy is not strict** with respect to paths.

> See: [Amit Klein’s research](http://lists.webappsec.org/pipermail/websecurity_lists.webappsec.org/2006-March/000843.html)

---

## TIP
- Use **dedicated domains** for authentication services:
  - E.g., `www.app.com` handles login and issues cookie for that FQDN only.
- Avoid shared domains between:
  - Authentication-sensitive services.
  - Publicly writable or third-party-facing content (e.g., blogs, user profiles).
- Do not rely on **path scoping** for cookie isolation.

---

## HACK STEPS

### **Domain Scope Review**
1. Review all cookies for `domain` attribute:
   - Liberal domain scope? → Potential cross-app/token exposure.

2. If scoped to own domain (no `domain` attribute), check for:
   - Any subdomains that might allow arbitrary script execution.

3. List all domains/subdomains receiving the cookie.
   - Investigate their exposure to attacker-controlled content or vulnerable applications.

---


## Summary Table

| Misconfiguration     | Risk                                                                 |
|----------------------|----------------------------------------------------------------------|
| Broad Domain Scope   | Tokens sent to untrusted subdomains or sibling apps                 |
| Parent Domain Scope  | Session cookies leak to test/dev or low-security apps               |
| Shared Hostnames     | Port/protocol differences don't prevent cookie access               |
| Path Restriction Use | Ineffective—sibling paths can access same-origin cookies            |
