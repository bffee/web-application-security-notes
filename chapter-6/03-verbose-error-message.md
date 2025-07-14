# Chapter 6 — Attacking Authentication

## Verbose Failure Messages

A **verbose failure message** tells the attacker exactly **which part** of the login attempt failed (e.g., "Username not found" vs. "Invalid password"). This helps attackers enumerate valid usernames.

---

### 🧠 Why It Matters

- **Username enumeration** makes brute-forcing easier and faster.
- Once a list of valid usernames is built, attackers can:
  - Launch password-guessing attacks
  - Target known users via social engineering or phishing
  - Explore password reset, change, or session-hijacking vectors

---

## ⚠️ Common Vulnerable Behaviors

### ❌ Verbose Login Responses

Apps that respond differently to:

- Invalid **username** → “No such user”
- Invalid **password** → “Wrong password”

→ Instantly give away whether a username is valid.

### ❌ Subtle Indicators

Even when error messages are **textually identical**, other indicators can give clues:

- Small **differences in HTML source** (e.g., comments, structure)
- Slight **response time variations**
- Different **redirect behaviors**
- Different **HTTP status codes** (e.g., 200 vs 302)

> 💡 **Burp Comparer** can detect minor response differences.

---

### ❌ Other Points of Leakage

Username enumeration isn’t limited to the login form:

- **Registration** pages (e.g., “Username already exists”)
- **Forgotten password** features
- **Change password** forms
- **Error messages** in internal tools or source code comments
- **Predictable usernames** (e.g., `user1001`, `user1002`)
- **Exposed email addresses** on contact pages

---

## 🔍 HACK STEPS: Enumerating Usernames

1. **Use a known valid username** (your own account, if possible):
   - Submit it with an **invalid password**.
   - Submit a **nonexistent username** with any password.
2. Carefully observe differences in:
   - Status codes
   - Response headers
   - On-screen messages
   - HTML source
   - Page structure or layout
3. Repeat on **all features** accepting usernames:
   - Registration
   - Forgot password
   - Change password
4. If a difference is found, use a **username wordlist** to automate detection.
   - Burp Intruder or custom script
   - Use “battering ram” mode to insert username as both the `username` and `password` (to catch weak creds).
5. If the app **locks accounts** after N failures:
   - Avoid wasting login attempts.
   - Use common passwords like `Password1` or the **username itself** as a test password.

---

## 🕒 Timing Attacks

Even when all visible differences are eliminated, **response times** can reveal validity:

- Valid usernames may trigger:
  - DB lookups
  - Account checks (expired, locked)
  - Hash computations
- Invalid usernames usually skip this work

### ⚠️ Challenge

- The difference might be just a few milliseconds
- Not detectable via browser
- But **automation** can catch it (e.g., Burp Intruder with response time columns)

---

## 💡 TIP: Mining Usernames from Other Sources

- **Email addresses** in source code, contact pages
- **Developer names or log entries**
- **User-generated content** (comments, forums)
- **Predictable naming schemes** (`j.doe`, `user123`)

---

Let me know when you're ready to continue to the next section: **Username Enumeration and Account Lockout**.
