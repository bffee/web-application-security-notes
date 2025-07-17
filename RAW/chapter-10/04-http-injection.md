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