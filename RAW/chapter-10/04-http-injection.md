## Injecting Into HTTP

Many web apps pull data from **back-end services** (like payment gateways, internal APIs, etc.) by taking a piece of user input and embedding it into an internal HTTP request. If they don’t **validate or sanitize** that input? Boom — you can inject whatever destination you want into that internal HTTP call.

---

## 🔍 Key Attack Vectors

Here are the two major attack classes this section explores:

### 1. **Server-Side HTTP Redirection Attacks**

* **Goal:** Force the app to fetch resources from arbitrary internal or external servers.
* **Mechanism:** Inject a full or partial URL in a user-controlled parameter.
* **Impact:** The app becomes a proxy—internal port scanner, SSRF portal, even a cross-site payload delivery tool.

### 2. **HTTP Parameter Injection (HPI) / HTTP Parameter Pollution (HPP)**

* **Goal:** Inject additional query/body parameters into the back-end HTTP request.
* **Impact:** Modify logic, override internal values, or perform business logic manipulation.

---

## 🚨 Example Payload: Server-Side HTTP Redirection

Let's say the app normally loads a CSS file like this:

```
POST /account/home HTTP/1.1
view=default&loc=online.wahh-blogs.net/css/wahh.css
```

You modify the `loc` parameter to:

```
loc=192.168.0.1:22
```

And the app responds with:

```
SSH-2.0-OpenSSH_4.2Protocol mismatch.
```

---

### ✅ Why This Works:

* The app **does not validate** the hostname or port.
* The app backend **accepts dynamic hostnames** and acts as a proxy.
* Port 22 is the default for SSH, so when the app connects, it receives the SSH banner — confirming successful access.

---

## 🎯 Real-World Exploitation Impact

If successful, you can:

1. **Scan internal IPs/ports** the public can't touch.
2. **Access loopback-only services** on `127.0.0.1`.
3. **Exploit authentication bypasses** due to trust relationships between internal services.
4. **Use the app as an open proxy** to attack other systems while hiding your identity.
5. **Inject HTML/JS from your server** into the app’s response → Cross-Site Scripting (XSS) payloads.

---

## 🛠️ HACK STEPS (Pentesting Workflow)

Here’s how to approach it step-by-step:

1. **Find Parameters with Hostnames, IPs, or URLs**
   Look for params like `url=`, `loc=`, `next=`, etc.

2. **Try Alternative URLs**
   Swap the URL with:

   * Internal IPs (e.g., `192.168.1.1`)
   * Ports (e.g., `192.168.1.1:3306` for MySQL)
   * Your own server (`http://yourserver.com/hello`)

3. **Check Response Time or Output**

   * No response from your server? → Might be blocked outbound.
   * Delayed response? → Likely timeout = app tried connecting = **vulnerable**.

4. **Advanced Exploits**

   * Internal **port scanning** with Burp Intruder.
   * SSRF into localhost (`127.0.0.1`).
   * Inject content (like XSS payloads) from your own server.

---

## 🧨 Dangerous APIs to Look Out For

### `Server.Transfer()` and `Server.Execute()` in ASP.NET

* These *only* allow **relative URLs**.
* But can still access **sensitive local paths** due to lack of proper isolation.

---

## 🧪 Practice Questions (Test Your Knowledge)

1. **Why is it dangerous when an application makes back-end HTTP requests based on user-supplied input?**

2. **If a parameter like `url=` accepts a value like `http://yourdomain.com/test`, how can you confirm it's being used in a back-end request?**

3. **What risks are posed if an attacker connects the app to `127.0.0.1:3306` via a vulnerable `url` parameter?**

4. **How could you use server-side HTTP redirection to perform a port scan? What tool helps here?**

5. **Why would including a full URL (with protocol and port) in a user-controlled parameter allow bypassing firewall rules or accessing internal services?**

---

### 🔍 **What is HTTP Parameter Injection?**

HTTP Parameter Injection happens when **user input is passed unsanitized into a back-end HTTP request** as parameters. This allows attackers to sneak in extra parameters that the server interprets as valid, potentially altering its behavior.

It’s similar to SSRF or command injection in spirit—**the app is trusting input too much and proxying it to something sensitive** (usually another internal service or script).

---

### ⚙️ **How the Front-End and Back-End Work Together**

Let’s consider this front-end request:

```
POST /bank/48/Default.aspx HTTP/1.0
Host: mdsec.net
Content-Length: 65

FromAccount=18281008&Amount=1430&ToAccount=08447656&Submit=Submit
```

This gets parsed and passed to a **back-end internal service** like this:

```
POST /doTransfer.asp HTTP/1.0
Host: mdsec-mgr.int.mdsec.net
Content-Length: 44

fromacc=18281008&amount=1430&toacc=08447656
```

At this point, the **internal server handles the actual bank transfer**. So if you can manipulate what's being sent in this second request... you win.

---

### 🚨 **What Makes It Vulnerable?**

The back-end accepts an extra parameter like:

```
clearedfunds=true
```

If this parameter is present, the back-end **skips validating whether the account has enough money**. Normally, the front-end shouldn’t send this. But if you can sneak it in, the money goes through—even if the account is empty.

---

### 🧠 **Payload Logic: How to Sneak in an Extra Parameter**

Here's how you inject `clearedfunds=true` from the front-end:

```
POST /bank/48/Default.aspx HTTP/1.0
Host: mdsec.net
Content-Length: 96

FromAccount=18281008&Amount=1430&ToAccount=08447656%26clearedfunds%3dtrue&Submit=Submit
```

> ✅ **Explanation of the Payload**
> You inject the string `&clearedfunds=true` into the **value of an existing parameter**, like `ToAccount`.
> To do this stealthily, you URL-encode:

* `&` as `%26`
* `=` as `%3d`

So this:

```
ToAccount=08447656%26clearedfunds%3dtrue
```

Becomes this when decoded by the server:

```
ToAccount=08447656&clearedfunds=true
```

> 💡 **Why this works:**
> The front-end app sees `ToAccount` as one string. But when it builds the back-end request, it **just slaps that value into the URL without validating it**, causing a new parameter (`clearedfunds=true`) to appear in the back-end request.

Here’s the final back-end payload:

```
POST /doTransfer.asp HTTP/1.0
Host: mdsec-mgr.int.mdsec.net
Content-Length: 62

fromacc=18281008&amount=1430&toacc=08447656&clearedfunds=true
```

The app **skips the cleared funds check**, and the transfer succeeds.

---

### 🧪 How to Detect It (Hack Steps)

1. **Find a Parameter Sink**
   Look for places where parameters are reused server-side—like payment, search, login, etc.

2. **Try Injecting Parameters**
   Use `%26param%3dvalue` in a parameter value and see how the app behaves.

3. **Look for Silent Success**
   Unlike SOAP, there’s often **no error on bad params**. The app may silently accept or ignore them unless you're hitting a real back-end trigger.

4. **Guess or Research Back-End Parameters**
   This part is hard in blackbox testing unless:

   * You know the tech stack (like ASP or PHP)
   * You can decompile mobile apps or JavaScript
   * You know the third-party component used on the back-end (many reuse known params)

---

### 💣 Real-World Tip

If the site uses a framework or internal API like `/internal/api/pay` or `/backoffice/doStuff`, you can often reverse-engineer the required parameters from leaked documentation or similar APIs. Also, tools like **Param Miner** in Burp Suite are helpful to auto-discover hidden or reflected parameters.

---

### ✅ Summary

| Concept          | Details                                                                                                  |
| ---------------- | -------------------------------------------------------------------------------------------------------- |
| 💥 Vulnerability | Unsanitized user input injected into back-end HTTP parameters                                            |
| 🧠 Core Logic    | Encoded characters `%26` and `%3d` trick the server into interpreting part of a value as a new parameter |
| 🔓 Impact        | Can bypass security logic like authentication, validation, or access controls                            |
| 🧪 Detection     | Try injecting extra parameters via encoded input; look for success or altered responses                  |
| 🔐 Defense       | Whitelist expected input; strictly validate and sanitize user-controlled values before internal reuse    |

---

## 🧬 Section: HTTP Parameter Pollution (HPP)

---

### 📌 What Is HPP?

**HTTP Parameter Pollution (HPP)** is an attack where **multiple parameters with the same name** are sent in a single HTTP request. Different back-end systems (or layers like WAFs, proxies, or frameworks) **handle these duplicates differently**, and that inconsistency can be weaponized.

> 🔥 In short: You send the same parameter twice. Depending on how the server parses it—first value, last value, merged value, etc.—you might be able to **override or inject behavior** that the app never expected.

---

### 🧠 How Servers Handle Duplicate Parameters

There’s no universal standard. Behavior varies by server, language, and framework. Here are the four **most common interpretations**:

| Server Behavior            | Effect                           |
| -------------------------- | -------------------------------- |
| **Use the first instance** | Ignores all later duplicates     |
| **Use the last instance**  | Overwrites earlier values        |
| **Concatenate values**     | Joins all values into one string |
| **Treat as array**         | Converts into a list/array       |

This ambiguity creates room for **attacks or bypasses**—especially when a front-end component handles one way, but a back-end component sees it differently.

---

### 💣 Exploiting HPP via Back-End Duplication

Let’s say this is the normal internal request sent by the app:

```
POST /doTransfer.asp HTTP/1.0
Host: mdsec-mgr.int.mdsec.net
Content-Length: 62

fromacc=18281008&amount=1430&clearedfunds=false&toacc=08447656
```

You want to **override** the `clearedfunds=false` parameter with `true`. But the app already sets `clearedfunds`—so you can’t just inject a new one... or can you?

If you inject this from the front-end:

```
FromAccount=18281008%26clearedfunds%3dtrue
```

The app will construct the back-end request like this:

```
fromacc=18281008&clearedfunds=true&amount=1430&clearedfunds=false&toacc=08447656
```

Now you have **two instances** of `clearedfunds`. If the back-end **uses the first instance**, your `true` value takes precedence, and the funds are marked as cleared. Boom—**bypass successful**.

---

### 📦 Payload Example + Logic Breakdown

Let’s walk through the actual front-end request:

```
POST /bank/52/Default.aspx HTTP/1.0
Host: mdsec.net
Content-Length: 96

FromAccount=18281008%26clearedfunds%3dtrue&Amount=1430&ToAccount=08447656&Submit=Submit
```

> 🧠 **Payload Logic:**

* You inject: `%26clearedfunds%3dtrue` (i.e., `&clearedfunds=true`)
* The `%26` becomes `&`, `%3d` becomes `=`, so the server reads:

  ```
  FromAccount=18281008&clearedfunds=true
  ```
* Now, if the **internal code already has**:

  ```
  clearedfunds=false
  ```

  and the back-end respects the **first instance**, your injected `true` value overrides the legit one.

> ✅ **Impact:**

* You bypass internal logic meant to block insufficient-fund transfers.
* Works because of a mismatch between how front-end and back-end handle duplicates.

---

### 🔁 Alternate Injection Point

If the back-end uses the **last instance of a duplicated parameter**, you can reverse your strategy. Inject the polluted param at the end, like in `ToAccount`:

```
ToAccount=08447656%26clearedfunds%3dtrue
```

Now the back-end sees:

```
clearedfunds=false&toacc=08447656&clearedfunds=true
```

Here, the last `clearedfunds=true` wins.

---

### 🔍 Why This Is Dangerous

* Front-end framework might sanitize or overwrite certain params
* But proxy/WAF may forward *both* values to the back-end
* Back-end logic processes them differently than what security controls see
* This can lead to logic bypasses, security rule evasion, or parameter smuggling

---

### 🔬 Try It Yourself

* [http://mdsec.net/bank/52/](http://mdsec.net/bank/52/)
* [http://mdsec.net/bank/57/](http://mdsec.net/bank/57/)

These two banks are configured differently—try injecting duplicate `clearedfunds` values and see how each one responds.

---

### 🛡️ Defense Strategy

| Layer             | Mitigation                                                  |
| ----------------- | ----------------------------------------------------------- |
| Input Handling    | Reject duplicated parameters unless explicitly allowed      |
| Web Server Config | Normalize requests and set canonical parsing behavior       |
| App Logic         | Use strict parsing (e.g., `req.query.param[0]`)             |
| WAF/Gateway       | Align behavior with back-end expectations to prevent bypass |

---

### 📚 Pro Tip

Multiple layers (e.g., WAF, load balancer, and back-end server) might **parse requests differently**. This opens up advanced attacks like **parameter smuggling**, which we’ll explore in Chapter 12. The [OWASP AppSec EU 2009 paper](https://www.owasp.org/images/b/ba/AppsecEU09_CarettoniDiPaola_v0.8.pdf) dives deep into how different servers behave.

---

### ✅ TL;DR Summary

| Key Point           | Details                                                                                    |
| ------------------- | ------------------------------------------------------------------------------------------ |
| 🎯 Vulnerability    | Duplicate parameter names parsed differently by different layers                           |
| 💥 Exploit Strategy | Inject polluted param before or after legit param, depending on parsing behavior           |
| 🧪 Detection        | Try `%26param%3dvalue` in different positions; observe response changes                    |
| 🔐 Defense          | Normalize parameter handling, disallow duplicates, ensure parsing consistency across stack |

---

## 🧠 Section: Attacks Against URL Translation — Explained

---

### 🔍 What's Going On Here?

Some applications transform friendly-looking URLs into something more functional behind the scenes. This process is called **URL translation** or **URL rewriting**.

For example:

```
/pub/user/marcus → gets rewritten as → /inc/user_mgr.php?mode=view&name=marcus
```

This is often done using rules in `.htaccess` (Apache’s `mod_rewrite`) or a backend router that maps URL paths to internal scripts or parameters.

---

### ⚠️ What’s the Vulnerability?

These translated URLs can become a weak point if:

1. **You can inject parameters** into the rewritten part of the URL (HPI – HTTP Parameter Injection).
2. **The backend allows duplicated parameters** and you can **override original values** (HPP – HTTP Parameter Pollution).

This means if a URL like this:

```
/pub/user/marcus%26mode=edit
```

...gets URL-decoded during rewriting, it might become:

```
/inc/user_mgr.php?mode=view&name=marcus&mode=edit
```

And now you’ve got **two `mode` parameters**, one benign (`view`) and one malicious (`edit`).

💥 If the server uses **the last occurrence**, your `edit` wins, and boom — you bypass front-end controls.

---

### 🧪 Let’s See This In Action – Payload Logic

**Original rewrite rule:**

```apache
RewriteRule ^pub/user/([^/\.]+)$ /inc/user_mgr.php?mode=view&name=$1
```

This turns:

```
/pub/user/marcus
```

into:

```
/inc/user_mgr.php?mode=view&name=marcus
```

---

### 🔥 Payload Example:

```
/pub/user/marcus%26mode=edit
```

#### 🔍 How This Works:

* `%26` = `&` → This makes the input effectively: `marcus&mode=edit`
* So now it rewrites to:

  ```
  /inc/user_mgr.php?mode=view&name=marcus&mode=edit
  ```
* If PHP uses **last occurrence wins**, then `mode=edit` takes over.
* Attacker goes from viewing Marcus's profile to editing it, **bypassing access controls**.

💡 The logic behind this attack is that:

* The **URL decoding** happens **before** the rewritten rule is applied.
* The value (`marcus%26mode=edit`) is interpreted as:

  * name = `marcus`
  * mode = `edit`

---

### 🧪 Alternate Encodings to Evade Filters:

Try injecting your extra parameters using different encodings to bypass WAFs:

* `%26foo%3dbar` → URL-encoded: `&foo=bar`
* `%3bfoo%3dbar` → URL-encoded: `;foo=bar` (some servers treat `;` as param separator)
* `%2526foo%253dbar` → Double-encoded `&foo=bar`, might bypass first-layer filters

---

### 🧠 Attack Workflow (Hack Steps Summary)

1. **Try injecting extra parameters** into URL path using encodings like `%26`, `%3b`, `%2526`, etc.
2. **Observe behavior** — does it behave like the original value was untouched? (could indicate injection worked)
3. **Attempt override** by injecting same parameter again (like `mode`) with your own value.
4. **Test whether you bypass frontend validation** (e.g., force `edit` mode while frontend sends only `view`).
5. **Use it for content discovery** — try replacing injected param with guesses like `admin=true`, `debug=1`, etc.
6. **Test various locations** — query string, cookies, POST body — and different param orders to maximize chances.

---

## 📚 Real-World Impact

* Can lead to **privilege escalation**, **bypassing role-based access**, or **modifying restricted resources**.
* Very effective in legacy PHP apps or those using URL rewriting.

---

## ✅ Practice Questions

1. **What allows an attacker to override a parameter value during URL translation?**
2. **Why does the `%26mode=edit` payload work during URL rewriting in PHP?**
3. **What role does parameter ordering play in successful parameter injection attacks?**
4. **How can you attempt to bypass WAFs when injecting parameters into rewritten URLs?**
5. **What might be the impact of successfully injecting `mode=edit` into a profile view URL?**

---