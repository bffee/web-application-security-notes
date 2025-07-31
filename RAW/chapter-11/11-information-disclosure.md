### 🧩 THE FUNCTIONALITY

This was a **newly deployed** financial web app — still buggy. Occasionally, something would break mid-request, and the app would show a **detailed debug error page** with the following:

* 👤 User’s identity
* 🔑 Session token
* 🌐 URL that was accessed
* 📦 Full request parameters (possibly with sensitive values like passwords, search queries, etc.)

To make troubleshooting easier for devs and support staff, this verbose info was displayed at a special error page URL, which the user was redirected to on failure.

---

### 🧠 THE ASSUMPTION

Dev team logic went something like this:

> “We’re not exposing anything the user doesn’t already know — they could just use browser dev tools to see their session ID, username, and request. So no risk.”

Unfortunately, they overlooked **two fatal flaws**:

1. 🔁 The debug message was stored in a **shared, non-session-scoped container**.
2. 🌍 The error display URL **always pointed to the last debug message**, regardless of who triggered it.

---

### 💥 THE ATTACK

#### ⚠️ What actually happened:

Let’s say:

* **User A** makes a request that fails — debug info gets stored.
* **User B** makes a request and gets redirected to the error message page.

Because the debug container was global, **User B now sees User A’s error message**, including **User A’s identity, session token, and request parameters**.

And now here’s the twist:

> ❗ An attacker doesn’t need perfect timing — they can just **poll the error page in a loop**, logging every change.

---

### 🔍 BEFORE vs. AFTER

#### 🟢 Expected Behavior (what devs assumed):

```
/debug?error=last
→ shows my debug info only
```

#### 🔴 Actual Behavior:

```
/debug?error=last
→ shows *whoever’s* debug info last hit the system
```

With continuous polling:

```bash
while true; do curl -s https://target.com/debug?error=last >> log.txt; sleep 1; done
```

You’re now collecting:

* `username=admin`
* `sessionID=abc123...`
* `params=password=Summer2025`
* and possibly PII or even app internals...

---

### 🧨 What Can an Attacker Do?

* 🔓 **Session Hijack** – use stolen tokens
* 🧠 **Username Harvesting** – for brute force or phishing
* 🔍 **Input Discovery** – see what other users are doing (email resets, passwords, search terms)
* ⚙️ **Recon** – analyze parameter names, functionality, internal APIs
* ☠️ **Privilege Escalation** – capture debug data from admin users

---

### 🌍 REAL-WORLD PARALLELS

This kind of mistake happens more than you'd think:

* 💻 Dev environments exposed to the internet (e.g., `/debug`, `/stacktrace`, `/logs`)
* 🧪 QA tools leaking session data (e.g., shared debugging dashboard)
* 🧵 Lack of **thread safety** in concurrent applications (multiple users writing to a shared buffer)

Even big companies have slipped up:

* GitHub once leaked private repo info due to **caching issues**.
* Facebook Graph API bugs that returned data cross-account.

---

### 🛠️ HACK STEPS

Here’s how *you’d approach exploiting or testing this flaw:*

1. ✅ **Trigger known errors** using malformed input (e.g., broken request parameters).
2. 👥 **Use two accounts** (or two sessions) — one to create an error, one to visit the debug page.
3. 🔁 **Poll the debug endpoint repeatedly** and log changes.
4. 🔍 Look for:

   * Username/session tokens not matching your current session
   * Input data from other users
   * Any sensitive internal values

---

### ✅ DEFENSE RECOMMENDATIONS

1. 🔒 **Never include sensitive info in error messages** — especially sessions, tokens, passwords.
2. 🛑 **Disable verbose debugging in production**.
3. 🔐 **Session-scope debug storage** — never use shared/global state for user-specific errors.
4. 📉 **Rate-limit** error page access or log polling.
5. 🕵️‍♂️ **Audit debug and logging endpoints** before deployment — even if “non-sensitive.”

---
