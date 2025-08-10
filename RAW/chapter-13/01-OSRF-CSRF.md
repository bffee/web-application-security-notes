## **Chapter Kickoff: Attacking Users – Other Techniques**

### **What This Means**

* Last chapter = **XSS**, the OG (grandfather) of attacks that target *other* users in a web app.
* This chapter = The *extended family* of attacks — techniques that:

  * **Work even when XSS isn’t possible**
  * Are sometimes **more complex, subtle, and harder to detect**
  * Can hit just as hard (sometimes harder) than XSS
* These attacks often slip past both developers and testers because:

  * They **don’t follow the obvious XSS pattern**
  * Vulnerabilities get **conflated** (different bugs confused as the same thing)
  * Or worse… they get **completely ignored**

---

### **Big Idea #1 — “Attacks Against Users” ≠ Just XSS**

Think of XSS as a flashy “inject script and hijack stuff” attack.
But here we’re looking at things that:

* Might **not inject any script at all**
* Could be **purely behavioral manipulation**
* Might abuse **browser features, HTTP quirks, or trust relationships**

---

### **Big Idea #2 — “Inducing User Actions”**

* With XSS, you can **trick a user’s browser** into sending requests they didn’t mean to.
* This works especially well if the victim:

  * Is **logged in**
  * Has **high privileges** (admin, moderator, etc.)
* Example: Admin sees your malicious payload → their browser silently makes a request to “Delete all user accounts” using *their own session*.

The chapter’s first focus is:

> How to make a victim’s browser **take an action you want** — even when the site has strong XSS protections.

---

### **Why This Matters in Real Life**

* These techniques can **completely compromise** an app through *the user*, not the server.
* They can be used in:

  * **Bug bounty hunting** (often high payouts)
  * **Penetration testing** (demonstrating “bypass” of secure dev claims)
  * **Real-world breaches** where an attacker can’t get code execution but can still get privilege escalation via social engineering + browser tricks.

---

✅ **Key Takeaways from the Intro**

1. XSS is *not* the end of the story — there are other user-targeted attacks.
2. These methods often **fly under the radar**.
3. First technique we’ll explore: **Inducing actions without needing XSS**.

---

## **Request Forgery (Session Riding)**

### **Core Concept**

* In **session hijacking**, you *steal* the user’s session token.
* In **request forgery**, you don’t need to *see* or *know* the token.
* Instead, you **trick the victim’s browser into sending a request** that *uses* their existing session token — because that’s just how browsers work.
* Browser automatically attaches:

  * **Cookies** for the site
  * **HTTP authentication headers**
  * Sometimes **CSRF tokens** if they’re stored in cookies/session

Result?
You make the victim’s browser perform actions **as them** — without them realizing.

---

### **Two Flavors**

1. **OSRF** (On-Site Request Forgery) → happens within the same site
2. **CSRF** (Cross-Site Request Forgery) → happens from a different site
   We’re focusing on **OSRF** here.

---

## **On-Site Request Forgery (OSRF)**

### **What It Is**

* You store something inside the site itself that causes *other users* to unknowingly make requests to different pages **on the same site**.
* Common misconception: OSRF requires **XSS**.
  Nope — you can pull it off without any JavaScript.

---

### **Example Attack**

#### **Scenario**: A message board

The app lets users post messages:

```
POST /submit.php
Host: wahh-app.com
Content-Length: 34

type=question&name=daf&message=foo
```

That gets rendered as:

```html
<tr>
  <td><img src="/images/question.gif"></td>
  <td>daf</td>
  <td>foo</td>
</tr>
```

---

#### **First Thought**: Try XSS

But `<` and `>` are HTML-encoded — so no `<script>` injection.

---

#### **Second Look**: The `<img src>` is partially user-controlled

The `type` parameter decides part of the image URL:

```
/images/[type].gif
```

Even if you can’t break out of the quotes, you can **change the path**:

```
../admin/newUser.php?username=daf2&password=0wned&role=admin#
```

The `<img>` now becomes:

```html
<img src="../admin/newUser.php?username=daf2&password=0wned&role=admin#.gif">
```

---

### **Why This Works**

1. Browser tries to **load the image**.
2. That "image" URL is actually a **GET request to /admin/newUser.php**.
3. If an **admin** is viewing the message:

   * The request is sent with **their session cookies**.
   * The server thinks *they* are adding the user.
4. `#` ends the URL so `.gif` is ignored (or `&` can be used to add `.gif` as a parameter).

Result: **New admin account created**.

---

### **No JavaScript Required**

* Even if JS is disabled, `<img>` tags still load.
* XSS prevention doesn’t stop this — because the payload doesn’t need `<script>`.

---

## **Key OSRF Characteristics**

* Works **inside the same domain**.
* Relies on:

  * **Automatic cookie sending** by the browser
  * **Application trusting the session cookie**
* Common injection points:

  * `href` in `<a>`
  * `src` in `<img>`, `<iframe>`, `<script>`
  * `action` in `<form>`

---

## **Hack Steps**

1. **Find places** where user-submitted content is displayed to others.
2. **Check for injection points** in URLs (`src`, `href`, `action`).
3. **Try path traversal or query string injection**:

   * `../target.php?action=deleteUser&id=123`
   * `/admin/addUser.php?role=admin`
4. **Pick high-impact requests**:

   * Account deletion
   * Role escalation
   * Config changes
5. **Test with a low-privilege account** → Then see what happens when an admin views it.

---

## **Defenses**

* **Strict allowlists** for parameters like `type`:

  ```php
  $allowedTypes = ['question', 'answer', 'info'];
  if (!in_array($type, $allowedTypes)) reject();
  ```
* **Block dangerous chars** `/ . \ ? & =`
* HTML-encoding doesn’t help → browser decodes before sending request
* Input validation before insertion into HTML attributes

---

## **Real-World Analogy**

Imagine a **guestbook** in a hotel lobby where guests can write messages to other guests.
You write:

> "Hey manager, go to the back room and turn off all the alarms."

The manager reads it and, without realizing, pushes the button next to your message.
**That’s OSRF** — you didn’t take his keys; you made *him* use them for you.

---

### **Modern Real-World Parallel**

* Bug bounty reports often find OSRF in **internal admin dashboards** that pull in user-generated data (support tickets, chat messages, etc.).
* If those dashboards include images or links with unsanitized URLs, attackers can sneak in OSRF payloads that execute powerful admin actions.

---

## **Cross-Site Request Forgery (CSRF)**

### **Core Idea**

* CSRF = You *don’t* need to steal a session token.
* You just make the victim’s **browser** send a **legit request** to the target site, **using the victim’s existing cookies**.
* Difference from OSRF:

  * OSRF payload **lives inside** the same application.
  * CSRF payload **lives outside** the app (on your malicious site, email, or even in an ad).
* **Key browser behavior exploited**: Browsers automatically attach cookies for the matching domain in *all* requests — even if the request comes from a completely different site.

---

## **Why CSRF Works**

* Same-Origin Policy (SOP) stops you from **reading** cross-domain responses.
* But SOP **does not stop** you from **sending** cross-domain requests.
* So CSRF is a **one-way attack**:

  * You can **send** requests to another site
  * But you can’t **read** the responses
* Still, “write-only” is enough to:

  * Change passwords
  * Transfer money
  * Create admin accounts
  * Delete data

---

## **The Perfect Storm for CSRF**

Three conditions make an app vulnerable:

1. **Privileged Action** — The request does something important (e.g., add admin user, change settings).
2. **Session Tracked Only by Cookies** — No unique per-request token in headers, URL, or body.
3. **Predictable Parameters** — Attacker knows exactly what fields to send.

If all three are true → **game on**.

---

## **Example Attack**

### **Target Request**

```
POST /auth/390/NewUserStep2.ashx HTTP/1.1
Host: mdsec.net
Cookie: SessionId=8299BE6B260193DA076383A2385B07B9
Content-Type: application/x-www-form-urlencoded

realname=daf&username=daf&userrole=admin&password=letmein1&confirmpassword=letmein1
```

---

### **Exploit HTML (Attacker’s Site)**

```html
<html>
<body>
<form action="https://mdsec.net/auth/390/NewUserStep2.ashx" method="POST">
  <input type="hidden" name="realname" value="daf">
  <input type="hidden" name="username" value="daf">
  <input type="hidden" name="userrole" value="admin">
  <input type="hidden" name="password" value="letmein1">
  <input type="hidden" name="confirmpassword" value="letmein1">
</form>
<script>
document.forms[0].submit();
</script>
</body>
</html>
```

---

### **Attack Flow**

1. Victim admin is logged into `mdsec.net`.
2. Admin visits attacker’s malicious webpage.
3. Hidden form **auto-submits** a POST request to `mdsec.net`.
4. Browser sends:

   * All hidden fields
   * Victim’s `SessionId` cookie
5. Server processes it as if *admin* submitted it.
6. New admin account created — attacker wins.

---

## **Real-World Example — eBay CSRF**

* A CSRF allowed **bids to be placed without consent**.
* Attackers could embed `<img>` tags in auction descriptions.
* App validated that the `<img>` loaded a real image — *once*.
* Attacker later swapped that image for a redirect to the malicious bid URL.
* Result: Anyone viewing the auction auto-placed a bid.
* Root cause: **TOCTOU flaw** (Time of Check, Time of Use) — the resource was trusted after initial validation.

---

## **Exploiting CSRF — Hack Steps**

1. **Identify target functions**:

   * Admin panel actions
   * Payment forms
   * Password reset endpoints
2. **Confirm cookies-only session tracking**:

   * No CSRF token
   * No custom header
   * No unpredictable parameter
3. **Craft malicious request**:

   * For GET → `<img src="https://target/action?...">`
   * For POST → hidden form + JS auto-submit
4. **Test**:

   * Stay logged into the app in one tab
   * Open malicious page in another
   * Verify the action executes
5. **Chain attacks**:

   * Combine with XSS
   * Trigger stored payloads
   * Force victim logins under attacker credentials

---

## **Chaining CSRF with Other Vulns**

* CSRF can turn a “low-risk” bug into a **critical impact**.
* Example from the book:

  * A SQL injection on an admin-only endpoint might be “low-risk” since only admins can run it.
  * But if CSRF can hit that endpoint → **anyone** can make an admin run malicious queries.

---

## **Authentication Bypass via CSRF**

* Many home routers have vulnerable admin pages.
* Users don’t change default IP or credentials.
* Two-stage CSRF:

  1. **Login CSRF** — attacker sends request with default creds → browser stores session cookie.
  2. **Action CSRF** — attacker sends second request to change router settings.

---

## **Stored XSS via CSRF Trick**

* Some sites let you upload files visible only to you.
* If you store XSS payload in such a file, it seems harmless — you can only attack yourself.
* But with CSRF:

  1. Force victim to log in as attacker
  2. Force victim to download attacker’s malicious file
  3. XSS executes in victim’s browser
  4. XSS persists, steals their real session after they log back in as themselves.

---

## **Defense Against CSRF**

1. **CSRF Tokens**:

   * Unpredictable per-request token tied to the session
   * Validated server-side
2. **SameSite Cookies**:

   * `SameSite=Lax` or `Strict` reduces CSRF risk
3. **Double Submit Cookie Pattern**:

   * Token in both cookie & request body
4. **Re-authentication**:

   * Require password confirmation for sensitive actions
5. **Content-Type Checks**:

   * Block `application/x-www-form-urlencoded` from external origins when not needed

---

💡 **Analogy**
OSRF is like slipping a note under someone’s office door telling them to sign a form *inside the building*.
CSRF is like mailing them a form disguised as a greeting card — they open it at home, but it actually signs the form and mails it for you.

---

## Preventing CSRF Flaws

CSRF (Cross-Site Request Forgery) exploits the way browsers automatically send session cookies to their associated web server with every request. When a web application relies solely on HTTP cookies to track sessions, it becomes inherently vulnerable to CSRF attacks.

### Standard CSRF Defense

The primary mitigation is to supplement HTTP cookies with additional session-verification mechanisms—most commonly, **anti-CSRF tokens**. These are unique, unpredictable values inserted into HTML forms (usually in hidden fields) and submitted alongside the request.

On receipt, the server validates both:

1. The normal session cookie
2. The correct anti-CSRF token

If the attacker cannot determine the token’s value, they cannot create a valid cross-domain request to execute the action.

> **Note:** Even functions protected with CSRF tokens can be compromised by **UI redress attacks** (covered later in this chapter).

### Token Security Considerations

Anti-CSRF tokens must be safeguarded like session tokens. Potential weaknesses include:

* **Predictable tokens** – An attacker who can guess or generate tokens can bypass CSRF defenses entirely.
* **Non-session-bound tokens** – If tokens are not tied to the specific session of the issuing user, an attacker can obtain a valid token in their own session and reuse it in a victim’s session.

### Brute-Forcing Anti-CSRF Tokens

Some applications use short anti-CSRF tokens under the assumption that brute-force attacks are impractical due to:

* High request volumes that could alert defenders
* Session termination after multiple invalid tokens

However, **client-side brute force** bypasses these constraints. Using browser-based history detection (via CSS and `getComputedStyle()`), an attacker can:

1. Generate a range of possible token values.
2. Embed them in links to the target site.
3. Detect which links the victim has visited (revealing valid tokens).

For this to work:

* The application must include the anti-CSRF token in the **URL query string** for some actions.
* The application must either:

  * Use the same token throughout a session, or
  * Accept token reuse.

Once a valid token is discovered, it can be used to perform sensitive operations on the victim’s behalf.

### Multi-Stage Operations Are Not Enough

Breaking a sensitive process into multiple steps (e.g., "enter details" → "confirm details") **does not** prevent CSRF unless each step uses its own anti-CSRF token. Without this, attackers can automate both requests or skip directly to the final step.

Similarly, setting a token in one response but then immediately redirecting to the next step **nullifies** the protection—because the browser follows the redirect and submits the token automatically.

### Weak Defenses

* **Relying on the Referer header** is insecure. It can be:

  * Spoofed (e.g., with older versions of Flash)
  * Suppressed (e.g., via meta refresh tags)
* Therefore, it should not be considered a reliable CSRF defense.

---

## Defeating Anti-CSRF Defense via XSS

### **1. The Claim & the Reality**

* **Common belief:** *“If an app has XSS, anti-CSRF is useless.”*
* **Reality:** *Partly true.*

  * XSS **can** bypass CSRF in many cases.
  * But if the **XSS is reflected** on a CSRF-protected page, it’s **not trivial**.

**Why?**

* In reflected XSS, your malicious payload is sent in the **initial request**.
* That initial request **must already contain a valid anti-CSRF token** if the target page enforces one.
* If you don’t have the token → request fails → vulnerable code never runs.

---

### **2. When XSS *Can* Defeat Anti-CSRF**

Here are the practical attack paths where anti-CSRF fails in the face of XSS:

#### **a) Stored XSS in CSRF-Protected Functionality**

* **Mechanism:**

  * Stored payload is already in the app’s database.
  * When the victim loads the page, the payload is served **with the valid anti-CSRF token in the same HTML response**.
  * Malicious JS can simply `document.querySelector()` or regex the token and send it with requests.
* **Outcome:** Tokens are useless because the attacker’s JS runs inside the token’s scope.

---

#### **b) Partial Anti-CSRF Coverage**

* **Example:**

  * **Step 1** of a funds transfer → No CSRF token required.
  * **Step 2** → CSRF-protected.
* **Exploit:**

  1. Attacker finds reflected XSS in *any unprotected function*.
  2. JS payload calls Step 1, gets the CSRF token from the response.
  3. Uses that token to execute Step 2 (protected step).
* **Lesson:** *CSRF protection must cover **all** related steps.*

---

#### **c) Tokens Bound to User, Not Session**

* **Setup:** Anti-CSRF token is tied to **user identity**, not the browser session.
* **Exploit:**

  1. Attacker logs into **their** account → gets token.
  2. CSRF attack forces victim to log in **as attacker** (no CSRF on login form).
  3. Victim unknowingly uses attacker’s account, where token matches.
  4. Attacker triggers XSS with that token in place → executes JS in victim’s browser.
  5. Optional: JS logs victim out → lures them to log back in → steals creds.

---

#### **d) Tokens Bound to Session, but Cookies Can Be Injected**

* **Scenario:** Attacker can plant cookies in victim’s browser.
* **Exploit:**

  1. Attacker sets **both** session cookie & matching anti-CSRF token cookie.
  2. Victim visits attacker’s payload → already in attacker’s “session”.
  3. XSS runs within attacker’s prepared session → CSRF protection collapses.

---

### **3. Takeaways for Pentesters**

* **Reflected XSS in CSRF-protected page** → harder to exploit but not impossible with multi-step tricks.
* **Stored XSS anywhere** → game over for CSRF.
* **Partial protection** or **token misuse** → exploitable chains exist.
* **Cookie injection + session-tied tokens** → possible bypass.

---

### **4. Why This Matters**

Even though CSRF tokens make reflected XSS harder to weaponize:

* Any **XSS vulnerability** should still be treated as critical.
* Chaining logic flaws + token handling weaknesses is standard red-team methodology.
* Proper defense = **fix XSS** + **full CSRF coverage** + **session-bound, unpredictable tokens**.

---

💡 **Real-world payload chain example:**

```javascript
// Inside a stored XSS payload:
let csrfToken = document.querySelector('input[name="csrf_token"]').value;
fetch('/transfer', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: `amount=1000&to=attacker&csrf_token=${csrfToken}`
});
```

In stored XSS, this works instantly because token + script are in the same response.

---

## **UI Redress (Clickjacking, Strokejacking, etc.)**

---

### **Core Concept**

* **CSRF vs. UI Redress:**

  * CSRF tries to *forge* requests without the user knowing, but can be stopped by anti-CSRF tokens.
  * UI redress works **even if CSRF tokens are present** by tricking the user into *legitimately* making the request inside the application.
* The reason it works:

  * The **user really is interacting** with the legitimate application in their browser session.
  * The anti-CSRF token is **present and valid**, because the real page is being used.

---

### **Attack Mechanics**

1. **Basic Setup**

   * Attacker embeds the target app inside an `<iframe>` on their malicious site.
   * The iframe is **visually disguised** or made **transparent** using CSS.
   * The attacker places enticing UI elements (e.g., game buttons, prize forms) that line up with sensitive buttons in the iframe.
   * When the victim clicks the attacker’s interface, they actually click the real app’s buttons underneath.

2. **Example — Bank Transfer Confirmation**

   * Step 1: Attacker sends the first CSRF-style request (e.g., initiate transfer) inside the iframe.
   * Step 2: Target app replies with confirmation page containing:

     * Transaction details
     * Hidden anti-CSRF token
     * “Confirm” button
   * Step 3: Attacker aligns a fake “Click here to win!” button with the real “Confirm” button.
   * Step 4: Victim clicks → **legit request is sent** with valid anti-CSRF token → funds transferred.

3. **CSS Tricks for Disguise**

   ```css
   iframe {
       position: absolute;
       top: 100px;   /* align with bait element */
       left: 50px;
       opacity: 0;   /* fully invisible */
       pointer-events: auto;
       z-index: 999;
   }
   ```

   * Adjusting iframe position and size
   * Cropping to only the target button area
   * Making it transparent

---

### **Advanced Variations**

#### 1. **Keystroke Hijacking**

* Attacker asks user to type something in a fake input.
* A script selectively **passes keystrokes** to the real app’s iframe.
* Example:

  * Target app’s “Amount” field needs `500`.
  * Attacker’s game asks user to enter their phone number to “verify a prize”.
  * Script sends only `500` into the bank form’s input.

```javascript
document.addEventListener('keydown', (e) => {
    if(['5','0'].includes(e.key)) {
        targetIframe.contentWindow.document.querySelector('#amount').value += e.key;
    }
});
```

---

#### 2. **Mouse Dragging Attacks**

* Victim plays a “drag-and-drop” game on attacker’s page.
* Mouse events are routed to the underlying iframe:

  * Drag email addresses into forwarding rules
  * Drag URLs containing session tokens into attacker’s form
* Links and images are especially dangerous because browsers send **full URLs** when dragging.

---

### **Why Anti-CSRF Tokens Fail Here**

* Token **is not stolen**, it’s used **legitimately**.
* The browser naturally submits it with the form because the victim’s session is active and the page is real.

---

## **Framebusting Defenses**

Old technique to stop embedding:

* Example framebusting JS:

  ```javascript
  if (top.location != self.location) {
      top.location = self.location;
  }
  ```
* **Problem:** All tested implementations have bypasses.
* Common bypasses:

  1. **Redefine `top.location`** in top frame so the child frame throws an exception.

     ```javascript
     var location = 'foo'; // attacker’s top frame code
     ```
  2. **Hook `onbeforeunload`** to break reload attempts.
  3. **Sandbox attribute**: disables scripts in child frame but keeps cookies active.
  4. **Trigger browser quirks**: e.g., IE’s XSS filter disabling child script.

---

## **Modern Defense — X-Frame-Options**

* HTTP header-based solution, supported by all major browsers.
* Options:

  * `X-Frame-Options: DENY` → never allow framing.
  * `X-Frame-Options: SAMEORIGIN` → allow framing only from same domain.
* Example:

  ```http
  HTTP/1.1 200 OK
  X-Frame-Options: DENY
  ```
* More modern replacement: **`Content-Security-Policy: frame-ancestors`**

  ```http
  Content-Security-Policy: frame-ancestors 'self';
  ```
* **Warning:**
  Mobile versions of sites are often unprotected — attacker can frame those even if main site is protected.

---

## **Practice Lab Ideas**

1. **Basic Clickjacking**

   * Host a page that loads a test banking app in an invisible iframe aligned with your “Claim Reward” button.
2. **Partial Overlay Attack**

   * Only expose the “Confirm” button area of iframe to reduce visual suspicion.
3. **Keystroke Redirection**

   * Implement a mini-game that passes certain keystrokes to an iframe field.
4. **Drag-and-Drop Data Theft**

   * Make a game where dragging an image actually drops data into a hidden target form.

---