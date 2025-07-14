# Weaknesses in Session Token Handling

Even if session tokens are **unpredictable and secure by design**, their **improper handling** can lead to session hijacking. Disclosure or insecure transmission can expose tokens to attackers.

---

## Common Misconceptions

- **“SSL guarantees token confidentiality.”**
  - SSL helps, but **misconfigurations**, **downgrade attacks**, or **mixed content** can expose tokens.

- **“Platform-generated tokens are always secure.”**
  - While generation may be robust, **handling practices** (e.g. token reuse or insecure transport) can create vulnerabilities.

---

## Disclosure of Tokens on the Network

Session tokens may be exposed **in cleartext** over HTTP or via **side channels**.

### Attack Scenarios

- **Unencrypted HTTP sessions**:
  - All data, including session tokens, is accessible to **network sniffers**.
  - Especially dangerous in public Wi-Fi or corporate networks.

- **HTTPS for login only, HTTP for rest**:
  - Tokens captured **post-authentication** can still hijack sessions.
  - Tools like **Firesheep** exploit this.

- **Token issued before login (on HTTP)**:
  - Token persists into the authenticated session.
  - Attacker can intercept token pre-login, then wait for login to occur.

- **Login downgrade attacks**:
  - If login is accepted over HTTP, an attacker can **force a login over HTTP**, capture the new token post-authentication.

- **Mixed content (HTTPS + HTTP)**:
  - Static resources (images, JS, CSS) fetched over HTTP **leak tokens** via `Referer` header or cookie transmission.
  - Browsers may warn users (see Figure 7-9), but the token is already exposed.

- **Forceful HTTP access**:
  - Even if the app uses HTTPS for everything, attacker can send a crafted HTTP link (e.g. `http://server:443/`) to trick user’s browser into submitting the token over plaintext.

---

## HACK STEPS

1. **Walk through the application flow**:
   - Start from homepage through login and post-authenticated actions.
   - Note every **new session token** received and **track HTTP/HTTPS transitions**.

2. **Verify Secure Flag**:
   - If using cookies, ensure the `Secure` flag is set.
   - Prevents cookie from being sent over non-HTTPS connections.

3. **Check for Token Leakage**:
   - Use tools like **Wireshark** or proxy logs (Burp Suite, OWASP ZAP).
   - Determine if any tokens are ever transmitted over HTTP.

4. **Evaluate Login Flow**:
   - Does login over HTTP succeed?
   - Does it issue a **new token** post-login, or reuse the pre-login token?

5. **Port 80 Exposure**:
   - Check if the server responds on port 80 (HTTP).
   - If so, visiting any link from an authenticated session may transmit token over HTTP.

6. **Test for Persistent Tokens**:
   - If a token is leaked via HTTP, test whether it **remains valid** or is **invalidated** by the server.

---

## Summary Table: Common Token Disclosure Vectors

| Vector                                     | Risk Type             | Vulnerability Description |
|-------------------------------------------|------------------------|----------------------------|
| Login over HTTPS but session over HTTP    | Token hijacking        | Token can be sniffed after login |
| Token issued before login, reused after   | Session upgrade flaw   | Pre-auth token can access authenticated resources |
| Mixed content loading                     | Side-channel leak      | Token sent in HTTP request headers |
| Downgrade login attack                    | Token interception     | Attacker forces login over HTTP |
| External HTTP requests                    | Forced disclosure      | Token sent by browser to HTTP URL |



## TIP

- Always enforce:
  - `Secure` and `HttpOnly` cookie flags
  - HTTPS across **all pages and resources**
  - **Automatic session token rotation** post-authentication
