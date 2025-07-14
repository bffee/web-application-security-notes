# Alternatives to Sessions

While most web applications use sessions to manage user state, some applications—especially security-critical ones—use **alternative mechanisms** to track users and maintain state without traditional session tokens.

---

## 1. HTTP Authentication

### Description

- Uses built-in browser support (e.g., **Basic**, **Digest**, **NTLM**) via **HTTP headers**.
- Once authenticated, the browser **resends credentials** with each request—eliminating the need for session tokens.

### Characteristics

- No reliance on application-managed session state.
- The browser handles authentication handshake and resubmission.
- Resembles a **form-based login on every page**, but managed by the browser, not by HTML forms.

### Limitations

- Rare in modern **Internet-facing applications** due to:
  - Poor UX
  - Lack of flexibility
  - Limited functionality compared to full session management

---

## 2. Sessionless State Mechanisms

### Description

- The application **does not maintain state on the server**.
- All state data is **sent to and returned from the client**, typically in:
  - Hidden form fields
  - Cookies

### Comparison to ViewState

- Works similarly to **ASP.NET ViewState**.
- A binary blob is created containing state data and is **signed or encrypted**.

### Requirements for Security

- Must **protect the blob** using strong signing/encryption.
- Must include **contextual information** to prevent replaying state in different app locations.
- Should implement **expiration times** for state objects to mimic session timeouts.

---

## Detection Indicators

| Indicator | Meaning |
|----------|---------|
| Data item is very long (100+ bytes) | Likely state blob |
| New item issued with every request | Stateless mechanism in use |
| Data appears encrypted or partially readable | Signed or encrypted blob |
| Same blob rejected if reused | Anti-replay logic in place |

---

## HACK STEPS

1. **Check for HTTP Authentication**
   - If used, session tokens may not exist.
   - Still investigate any cookie, header, or hidden field for token-like behavior.

2. **Identify Sessionless State Mechanisms**
   - Look for signs like:
     - Long data values sent in cookies or forms.
     - New data issued per request.
     - Values with structured data + hash/encrypted tail.

3. **Decision Making**
   - If no server-side session is used, traditional session attacks likely won’t work.
   - Focus efforts instead on:
     - **Access control issues**
     - **Injection vulnerabilities**
     - **Weak state protection**

---

## Summary Table

| Alternative           | Description                                        | Risk / Limitation                 |
|----------------------|----------------------------------------------------|-----------------------------------|
| HTTP Authentication  | Credentials sent in each request via browser       | Poor UX, not flexible             |
| Sessionless State     | State stored client-side in secure blobs           | Vulnerable if not properly secured|

