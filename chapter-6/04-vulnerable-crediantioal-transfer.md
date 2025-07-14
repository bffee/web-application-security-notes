# Chapter 6 — Attacking Authentication

## Vulnerable Transmission of Credentials

Even the strongest authentication logic is **meaningless** if credentials are exposed in transit. A common mistake is failing to ensure **secure transport**, especially when transmitting login data.

---

## 🚨 Core Risk

If login credentials are transmitted over **unencrypted channels** (HTTP), they can be **intercepted** by any party positioned on the network between the user and the server, including:

- 🧑‍💻 Local attackers on public Wi-Fi
- 🧑‍💼 Corporate IT staff (legitimate or compromised)
- 🛰 ISPs or Internet backbone entities
- 📡 Malicious actors who’ve compromised routers, proxies, or infrastructure

---

## 🔓 Unsafe Credential Transmission Methods

### ❌ Login via HTTP
- Submitting credentials over plain HTTP exposes them to **network sniffing**.
- Attackers can use tools like Wireshark to grab passwords in real time.

### ❌ Credentials in **URL Query Strings**
```http
GET /login?user=john&pass=123456 HTTP/1.1
```
- Logged in:
  - Browser history
  - Proxy logs
  - Web server logs
  - Application firewalls

### ❌ Credentials in Cookies
- Sometimes used for:
  - "Remember me" features
  - Session persistence
  - Password change flows
- Vulnerable to:
  - Cross-site scripting (XSS)
  - Local file access
  - Replay attacks (even if encrypted)

### ❌ Login Page Loaded over HTTP
- Even if submission uses HTTPS:
  - A MITM attacker can tamper with the login **form action**, changing HTTPS to HTTP.
  - Users **can’t validate the page origin**, opening phishing and redirection risks.

---

## 🛡 Correct Practice

| Aspect                        | Secure Implementation                                      |
|------------------------------|-------------------------------------------------------------|
| Transport Protocol           | Use HTTPS **end-to-end** (including the login page itself) |
| Credential Submission        | Use **POST body**, never query string                      |
| Persistent Login             | Use secure session tokens, not raw credentials in cookies  |
| Login Page Delivery          | Load login pages via HTTPS only                            |

---

## 🔍 HACK STEPS

1. **Monitor traffic** during login (proxy like Burp Suite):
   - Look for credentials sent in **query strings**, **cookies**, or over **HTTP**.
2. If found:
   - Try to understand why this design was chosen.
   - See if it can be **manipulated or replayed**.
3. Test whether any sensitive values are **encoded/obfuscated** instead of encrypted:
   - Try reversing it.
   - Look for patterns in hex/base64/URL encoding.
4. If credentials use HTTPS **but login page loads over HTTP**:
   - Modify the form action to an HTTP endpoint.
   - See if the app submits creds over HTTP.
5. Consider potential **man-in-the-middle (MITM)** scenarios:
   - Capture and tamper with responses using tools like `mitmproxy` or custom scripts.

---

## 📌 Summary

| Unsafe Practice                            | Exploit Risk                                       |
|--------------------------------------------|---------------------------------------------------|
| HTTP login submission                      | Full credential theft                             |
| Login form delivered via HTTP              | MITM alteration of login action                   |
| Credentials in URL query or cookies        | Stored in logs, browser, vulnerable to replay     |
| Encoding/obfuscation without encryption    | Reverse-engineering, replay, and impersonation    |

---

Let me know when you're ready to continue to the next section: **Username Enumeration and Account Lockout**.
