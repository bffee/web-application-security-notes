# “Remember Me” Functionality

“Remember Me” features are common in web applications as a convenience mechanism. However, their implementations are often insecure, introducing critical authentication bypass vulnerabilities or enabling user impersonation.

---

## Common Implementation Flaws

### 1. Persistent Username Cookie
- Some apps store a username in a long-lived cookie, e.g.:
  ```
  RememberUser=daf
  ```
- The application reads the cookie and logs the user in **without verifying a password**.
- This allows an attacker to:
  - Enumerate usernames
  - Set the cookie to impersonate users
  - Gain access without any authentication

### 2. Predictable Identifier Tokens
- Instead of a username, some cookies store a persistent ID, e.g.:
  ```
  RememberUser=1328
  ```
- The application uses this ID to look up and log in the corresponding user.
- If identifiers are:
  - Sequential
  - Guessable
  - Short in length  
  → Attackers can brute-force or iterate through them to gain access.

- Refer to Chapter 7 for techniques to analyze and exploit predictable tokens.

### 3. Local or Client-Side Exposure
Even when data is encrypted or encoded:
- It can still be:
  - Captured via **cross-site scripting (XSS)** (see Chapter 12)
  - Stolen by someone with **local access** to the user’s machine
- Other storage vectors include:
  - Flash Local Shared Objects
  - Silverlight Isolated Storage
  - Internet Explorer’s `userData`

---

## HACK STEPS

1. **Test "Remember Me" functionality**
   - Enable it using a test account.
   - Close and reopen the browser, revisit the app.
   - Observe if the application:
     - Logs in completely
     - Only pre-fills the username (less risky)

2. **Inspect all persistent client-side storage**
   - Look at:
     - Long-lived cookies
     - Local storage
     - Flash/ActiveX/Silverlight
   - Identify anything that looks like a:
     - Username
     - User ID
     - Token
     - Encoded string

3. **Try reverse-engineering stored data**
   - Compare cookies across:
     - Different accounts
     - Slightly altered usernames/passwords
   - Look for:
     - Reused patterns
     - Encoded identifiers
     - Partial plaintext

4. **Modify cookie/token values**
   - Replace cookie values with those of:
     - Another user (if known)
     - A nearby/adjacent ID
     - A guessed username
   - Observe if the application logs in as another user.

---

## TIP

Even if the stored data is encrypted or opaque, **don’t assume it’s secure**. Use the same analytical techniques described for session token analysis (Chapter 7) to determine:

- Predictability  
- Reversibility  
- Collisions  

Also remember:
- Cookie data is **often reused** between sessions.
- Any captured or replayed value may be sufficient to **bypass authentication entirely**.
- XSS or local access can convert a theoretical flaw into a full compromise.

---

## Summary Table

| Vulnerability Type           | Description                                                                       |
|-----------------------------|-----------------------------------------------------------------------------------|
| Username-based auto-login   | Cookie stores only the username; no password verification required                |
| Predictable user identifiers| Identifiers like `1328` can be brute-forced to log in as other users              |
| Client-side storage exposure| Stored data (cookies, Flash, Silverlight) is accessible via XSS or local attack   |
| Replayable persistent tokens| Tokens may be encrypted, but are still replayable for full session hijack         |
