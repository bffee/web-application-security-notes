# Chapter 6 — Attacking Authentication

## Overview

Although **authentication** appears simple — verifying a username and password — it's a **critical security mechanism** and **often the weakest link** in web applications. If authentication is compromised, attackers often gain **full control** of functionality and data.

---

## Importance of Authentication

- **Front line of defense** against unauthorized access.
- **Other security mechanisms (session management, access control, etc.) rely on it.**
- Many applications fail due to **defects in authentication logic**, even though attacks can be very basic (e.g., password guessing) or extremely subtle (multi-stage bypasses).

---

## Authentication Technologies

Various technologies are used to implement authentication in web applications:

### 1. **HTML Forms-Based Authentication**
- Most common (90%+ of internet applications).
- User inputs credentials via an HTML form (username/password).
- Often used with **additional credentials** (e.g., PIN, secret word) in security-sensitive apps.

### 2. **Multifactor Authentication (MFA)**
- Combines:
  - Passwords
  - Physical tokens (e.g., OTP generators, challenge-response devices)
- Common in high-security apps like **private banking**.
- Often ineffective against threats like **phishing** and **client-side malware**.

### 3. **Client SSL Certificates / Smartcards**
- High administrative overhead.
- Typically used in **small-scale** but **high-security** contexts (e.g., corporate VPNs).

### 4. **HTTP Basic, Digest, and Windows Integrated Auth**
- Rare on the public internet.
- Common in **intranets**, where users are authenticated via **domain credentials** (NTLM/Kerberos).

### 5. **Third-Party Authentication Services**
- E.g., Microsoft Passport.
- Not widely adopted at scale.

> ⚠️ **Most vulnerabilities apply across all these technologies.**  
> Examples are discussed primarily in the context of **HTML forms**, the most prevalent method.

---

## Design Flaws in Authentication Mechanisms

Authentication is **frequently flawed by design**. Even the basic username/password model can have serious oversights.

---

### ❌ Bad Password Policies

Many applications allow insecure passwords. Examples:

- **Very short or blank**
- **Common dictionary words or names**
- **Password = username**
- **Still using default password**


> 💡 **Most users don’t understand security.** If weak passwords are allowed, many will choose them.

---

### 🔍 HACK STEPS

To identify weak password rules:

1. **Check documentation or help pages** on the site for any mention of password requirements.
2. If **self-registration is available**, try registering accounts with weak passwords (e.g., `123`, `admin`, blank).
3. If you can **change your password**, attempt to set it to weak values and see if they’re accepted.

> 📌 **Note**: If enforcement happens **only on the client side** (e.g., via JavaScript), it's not a major issue *by itself*, since most users will still be prevented from using weak passwords.  
> The real issue is if the **server accepts** weak passwords regardless of client-side enforcement.

---
