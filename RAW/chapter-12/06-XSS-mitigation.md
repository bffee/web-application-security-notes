## 🛡️ Preventing XSS Attacks — Overview

While XSS attacks come in various forms, **preventing them is conceptually simple**:
Just **don’t trust user data** and **don’t let it control your page**.

### 💥 The Problem:

Modern web apps handle **lots of user data** — in inputs, profiles, error messages, URLs, etc.
Finding and fixing **every** place where user data could be dangerous is **hard**.

There are **3 types of XSS**, and each needs a tailored defense:

* Reflected XSS
* Stored XSS
* DOM-based XSS

Let’s go step by step.

---

## 🧱 Part 1: Preventing Reflected and Stored XSS

Both types happen when **user input** is added to a page **without proper checks**.

### 💣 The Danger:

When raw user data is inserted into HTML, it can:

* **Break HTML structure**
* **Inject new tags or scripts**
* **Run malicious JavaScript**

### ✅ Fix: Use This 3-Step Defense Strategy

> Think of it as a “defense triangle” for traditional XSS:

#### 1. **Validate Input** (on entry)

Make sure data looks like what you expect:

* Not too long
* Only valid characters (e.g., letters, numbers)
* Matches a strict regex

Example:
A username field should only allow letters and numbers:

```regex
^[a-zA-Z0-9]+$
```

#### 2. **Validate Output** (on display)

Before showing user data in HTML, **encode special characters**:

| Character | Encoded As |
| --------- | ---------- |
| `<`       | `&lt;`     |
| `>`       | `&gt;`     |
| `&`       | `&amp;`    |
| `"`       | `&quot;`   |
| `'`       | `&apos;`   |

Example:
If user input is:

```html
<script>alert(1)</script>
```

After encoding:

```html
&lt;script&gt;alert(1)&lt;/script&gt;
```

This way, the browser sees it as **text**, not **code**.

#### 3. **Avoid Dangerous Insertion Points**

Some places are **too risky** to allow user input, like:

* Inside `<script>` blocks
* Inside event handlers (e.g., `onclick=`)
* In `src`, `href`, or `style` attributes
* In HTML that controls the **character set** (e.g., `charset=utf-7`)

If possible, **don’t allow user input here at all**.

---

## 💡 Examples of Output Encoding Fails

Attackers can **bypass naive encoding** if it’s done wrong.

Bad Example:

```html
<img src="javascript&#58;alert(document.cookie)">
```

Another one:

```html
<img src="image.gif" onload="alert('xss')">
```

Lesson: **Just encoding characters isn’t enough**. The safest option is to:

* Escape user input **before inserting into any dangerous context**
* Encode **all non-alphanumeric characters**

---

## 🛠️ Developer Tools for Sanitization

### ✅ ASP.NET:

Use built-in `Server.HTMLEncode` function:

```csharp
Server.HTMLEncode("<script>alert(1)</script>");
```

### ✅ Java:

No built-in HTML encoder, but you can build your own:

```java
public static String HTMLEncode(String s) {
  StringBuffer out = new StringBuffer();
  for (int i = 0; i < s.length(); i++) {
    char c = s.charAt(i);
    if (c > 0x7f || c == '"' || c == '&' || c == '<' || c == '>') {
      out.append("&#" + (int)c + ";");
    } else {
      out.append(c);
    }
  }
  return out.toString();
}
```

### 🧨 Common Mistake:

Only encoding the character you think is dangerous, like just `"` or just `>`.
Hackers **abuse this** by mixing multiple fields or using creative syntax.

✅ Better: Encode **everything that's not a letter or number**.

---

## ✨ Defense in Depth

Why do **both input validation** and **output encoding**?

* If one layer fails (e.g., encoding is buggy), the other catches it.
* But: **Output encoding is mandatory. Input validation is a backup.**

Also:

* Perform encoding **after canonicalization** (e.g., URL-decoding)
* Watch for NULL byte attacks
* Always define a specific charset (e.g., `charset=UTF-8`)

---

## 📝 What About Allowing HTML?

Sometimes users are allowed to use **limited HTML** (e.g., blog comments).

Problem: If you encode their HTML, it just shows up as plain text.

### ✅ Solution: Use a **strict whitelist**

Allow only safe tags and attributes. Reject everything else.

Bad Example:

```html
<b style="behavior:url(#default#time2)" onbegin="alert(1)">
```

Even `<a href="...">` can be dangerous:

```html
<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
```

### 🔧 Tools:

* **[OWASP AntiSamy](https://owasp.org/www-project-antisamy/)** – a framework to allow only safe HTML
* Custom markup (e.g., BBCode or Markdown) is a safer alternative

---

## 🧠 Part 2: Preventing DOM-Based XSS

This type is different because the vulnerable code runs **entirely in JavaScript**, not on the server.

Example:

```html
<script>
  var a = document.URL;
  document.write(a); // vulnerable
</script>
```

### ✅ DOM-Based Defenses:

#### 1. Validate Input (JavaScript-side)

Example:

```javascript
var a = document.URL;
a = a.substring(a.indexOf("message=") + 8);
a = unescape(a);

var regex = /^([A-Za-z0-9+\s])*$/;
if (regex.test(a)) {
  document.write(a);
}
```

Also do **server-side validation**:

* Only allow expected parameters
* Reject if anything weird is found

#### 2. Validate Output (Client-Side)

Before inserting DOM data into the page, **sanitize it**:

```javascript
function sanitize(str) {
  var d = document.createElement('div');
  d.appendChild(document.createTextNode(str));
  return d.innerHTML;
}
```

This function encodes everything safely by using the browser’s own parser.

---

## 🔚 Final Summary

### 🔐 XSS Defense Strategy:

| Step | Technique                        | Applies To         |
| ---- | -------------------------------- | ------------------ |
| 1    | Validate Input                   | Server and Client  |
| 2    | Encode Output                    | Always             |
| 3    | Avoid Dangerous Insertion Points | Always             |
| 4    | Use Whitelisting                 | When allowing HTML |
| 5    | Use Sanitize Functions           | DOM-based XSS      |

---

### ✅ Pro Tip Recap:

* Never insert raw user input directly into HTML/JS.
* Encode output **everywhere**, even if you “trust” the input.
* Don’t allow users to control the page’s charset.
* DOM-based XSS is sneaky. Use sanitize functions and avoid `document.write`.

---