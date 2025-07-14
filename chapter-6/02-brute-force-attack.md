# Chapter 6 — Attacking Authentication

## Brute-Forcible Login

Login forms inherently **invite brute-force attacks**, where an attacker tries multiple passwords for one or more usernames until successful access is gained.

---

## Why This Is Dangerous

- Attackers can **automate password guessing** using tools and scripts.
- Common passwords (e.g., `123456`, `password`, `letmein`) are widely used.
- Even "secure" passwords are breakable over time if the app doesn’t defend against high-rate login attempts.

> 🧠 **Note:** Admin credentials are often weaker than policies suggest due to:
> - Pre-policy account setup
> - Separate management interfaces with relaxed rules

---

## Real-World Stats: Common Passwords

Many real-world password breaches revealed these as top choices:

- `password`
- `12345678`
- `qwerty`
- `abc123`
- `letmein`
- `111111`
- `12345`
- `monkey`
- (and even the **website name**)

---

## Automation Example: Burp Intruder

Burp Intruder can automate login attempts. Differences in response:

- HTTP status code
- Response length
- Presence or absence of error strings (e.g., “login incorrect”)

> 📷 Figure 6-2 (not shown) highlights a successful brute-force login detected via changed response behavior.

---

## Poor Mitigations That Fail

### ❌ Client-Side Login Counters

Some apps use **cookies like `failedlogins=1`** to track failed attempts.
- Completely bypassable: attacker can reset cookies or modify requests manually.

### ❌ Session-Based Lockouts

Some apps track failures per session.
- Attacker simply resets the session (e.g., by clearing cookies) and continues.

### ❌ Leaky Lockouts

App locks an account but **still leaks feedback**:
- If a correct password is submitted to a locked account, the **response differs** from invalid ones.
- Allows the attacker to finish guessing the correct password **even after lockout**.

### ❌ Auto-Unlock

If accounts **auto-unlock after a delay**, an attacker can:
1. Guess the correct password during lockout.
2. Wait until unlock.
3. Login successfully with the found password.

---

## 🔍 HACK STEPS: Brute-Force Evaluation

1. **Submit invalid logins** manually and observe error messages.
2. After ~10 bad attempts, try a valid login. If it succeeds ➝ **No lockout policy.**
3. If lockout **is** triggered:
   - Repeat using **different cookies/sessions**.
   - Submit the correct password to see if the response differs from an incorrect one.
4. If **no account access**, try brute-forcing a **known or guessed username** to test lockout behavior.

---

## 🚀 Launching a Brute-Force Attack

1. **Identify response differences** between valid and invalid logins (e.g., size, error message).
2. Gather:
   - A list of **valid or likely usernames**
   - A **password wordlist**, customized based on any known policy rules.
3. Use **Burp Intruder**, **Hydra**, or a **custom script** to:
   - Generate login permutations
   - Analyze server responses for successful attempts

---

### ⚖️ Depth-First vs Breadth-First Attacks

- **Depth-First**: Try all passwords for one username → more likely to trigger lockouts.
- **Breadth-First**: Try one password across all usernames → better for:
  - Avoiding lockouts
  - Quickly finding weak passwords reused across multiple users

---

Let me know when you're ready for the next section: **Username Enumeration**.
