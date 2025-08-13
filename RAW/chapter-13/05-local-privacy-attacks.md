# **Local Privacy Attacks**

These attacks occur when an attacker has **physical or local access** to the victim’s device, either temporarily (shared workstations, stolen devices) or persistently (insider threat, family member snooping).
Modern applications, especially **progressive web apps (PWAs)**, hybrid apps, and HTML5-heavy web apps, often store significant amounts of sensitive data locally.

> **Key point:** A local attacker doesn't need advanced exploitation skills — if sensitive data is stored insecurely, they just need file access.

---

### **1. Persistent Cookies**

**Risk:** Even if encrypted, session cookies or authentication tokens stored persistently can be stolen and replayed.

**Modern Example:**

```http
Set-Cookie: sessionId=eyJhbGciOiJIUzI1NiIsInR5cCI6...; 
            Expires=Wed, 12 Aug 2026 12:00:00 GMT; 
            Secure; HttpOnly; SameSite=Strict
```

If `Expires` or `Max-Age` is set to a future date, the cookie persists.

**Hack Steps (2025):**

1. Intercept cookies with **browser dev tools** → `Application > Cookies`.
2. Look for:

   * `Expires` far in the future
   * Sensitive tokens (JWTs, API keys, re-auth tokens)
3. Check for replayability using **Burp Repeater** or `curl`.

**Replay Attack Example:**

```bash
curl -b "sessionId=<stolen_cookie>" https://target.com/dashboard
```

**Modern Storage Paths:**

* **Chrome / Edge (Win10+)**:
  `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Cookies` (SQLite DB)
* **Firefox (Linux)**:
  `~/.mozilla/firefox/<profile>/cookies.sqlite`

---

### **2. Cached Web Content**

**Risk:** Browsers cache HTML, JS, and JSON containing sensitive data if caching headers are missing.
Even **service workers** can store sensitive pages offline in PWA caches.

**Hack Steps:**

1. Visit target page with sensitive data (e.g., `/account/transactions`).
2. Check HTTP headers for:

   ```http
   Cache-Control: no-store, no-cache, must-revalidate
   Pragma: no-cache
   Expires: 0
   ```
3. If missing, dump cache:

   * Chrome DevTools → `Application > Cache Storage` and `IndexedDB`
   * Inspect `%LocalAppData%\Google\Chrome\User Data\Default\Cache`

**PWA Risk:** Service workers may store *full API JSON responses* in `CacheStorage` for offline use.

**PWA Cache Dump Example (JS):**

```javascript
caches.keys().then(names => {
  for (let name of names)
    caches.open(name).then(cache =>
      cache.keys().then(keys => console.log(keys))
    );
});
```

---

### **3. Browsing History**

**Risk:** If sensitive data is in the URL query string, it will be stored in:

* Browser history
* System jump lists (Windows)
* Router logs

**Example:**

```
https://bank.com/transfer?amount=5000&account=987654321
```

**Hack Steps:**

1. Search history DB:

   * Chrome:
     `%LocalAppData%\Google\Chrome\User Data\Default\History` (SQLite)

     ```sql
     SELECT url FROM urls WHERE url LIKE '%account=%';
     ```
2. Check for **URL parameter leaks** in sensitive workflows.

---

### **4. Autocomplete**

**Risk:** Browsers save usernames, passwords, addresses, card numbers — even in non-password fields — unless explicitly disabled.

**Hack Steps:**

1. Inspect form fields in HTML:

   ```html
   <input type="text" name="creditcard" autocomplete="off">
   ```

   If missing, sensitive data may be stored.
2. On victim's machine:

   * Chrome: `Login Data` SQLite DB
   * Firefox: `logins.json`

---

### **5. Flash LSOs / Silverlight / Legacy Storage**

**Risk:** Legacy tech is mostly dead in 2025, but in older enterprise environments, remnants can exist.

* Flash LSOs: `#SharedObjects` directory
* Silverlight: `%AppData%\LocalLow\Microsoft\Silverlight\is`

> **Modern note:** These are rare today, but pentesters should still scan for `.sol` or `.is` files in forensic engagements.

---

### **6. HTML5+ Local Storage Mechanisms (Modern Main Risk Area)**

Modern apps use:

* **localStorage** (persistent key-value)
* **sessionStorage** (per-tab storage)
* **IndexedDB** (structured DB)
* **CacheStorage** (service workers)
* **WebSQL** (deprecated but still found)
* **File System Access API** (Chrome-specific)

**Hack Steps:**

1. Open browser dev tools → `Application` tab.
2. Inspect:

   * **localStorage** for tokens, PII
   * **IndexedDB** for cached API responses
   * **CacheStorage** for offline resources
3. Dump storage programmatically:

   ```javascript
   console.log(JSON.stringify(localStorage));
   indexedDB.databases().then(dbs => console.log(dbs));
   ```

**Example LocalStorage Vulnerability:**

```javascript
// Found in victim's browser
localStorage.setItem("authToken", "eyJhbGciOiJIUzI1NiIsInR5cCI6...");
```

Replay with:

```bash
curl -H "Authorization: Bearer <token>" https://target.com/api/me
```

---

### **7. Mitigation Guidelines (2025)**

* **Never** store plaintext credentials or tokens in persistent client-side storage.
* For tokens:

  * Use **HttpOnly Secure Cookies** (short-lived)
  * Avoid localStorage for auth unless encrypted & bound to device
* Use:

  ```http
  Cache-Control: no-store, no-cache, must-revalidate
  Pragma: no-cache
  Expires: 0
  ```
* Avoid sensitive data in URLs — use POST.
* Disable autocomplete for sensitive fields:

  ```html
  autocomplete="off"
  ```
* For PWAs:

  * Encrypt cached API responses
  * Purge cache on logout
  * Require online validation for sensitive actions

---