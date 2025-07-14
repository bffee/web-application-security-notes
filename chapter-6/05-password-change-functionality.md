# 🔐 Password Change Functionality

## ✅ Why It’s Necessary

1. **Periodic password changes** reduce the window of opportunity for brute-force or stolen credentials to be abused.

2. **Self-service recovery** lets users change compromised passwords quickly.

Yet despite its importance, the **password change function is often insecurely implemented**, even in applications with hardened login flows.

---

## ⚠️ Common Vulnerabilities in Password Change Logic

### ❌ No Authentication Required
- The password change page is accessible without a valid session or login, allowing unauthorized access.

### 🔍 Verbose Error Messages
- The system reveals whether a username or account exists, aiding attackers in user enumeration.

### 🎯 Brute-Forcible Current Password
- There's no rate-limiting or lockout mechanism for verifying the current password, enabling brute-force attacks.

### 🔁 Validation Ordering Flaw
- The system validates the new password and confirmation match **before** verifying the current password.  
- This allows non-invasive brute-force attempts on the old password (e.g., by observing which error is returned first).

### 🧠 Overly Complex Logic
- Excessive branching for validation, error handling, or account lockout can introduce subtle bugs or inconsistencies, making the system hard to test and secure.



---

## 🧪 HACK STEPS

### 🔎 1. Locate the Password Change Feature
- May not be directly linked.
- Use **brute-force content discovery** (e.g., `changepassword`, `update-password`, `account/edit`) as discussed in Chapter 4.

### 🧪 2. Probe for Weaknesses
Perform tests with:
- ❌ **Invalid usernames**
- ❌ **Incorrect current passwords**
- ❌ **Mismatched `new` and `confirm` values**

Watch for:
- Differences in error messages → **username enumeration**
- No rate-limiting → **brute-force vector**
- Order of validation → can help isolate current password validity

---

## 🧠 Advanced Exploitation Tip

Even if the password change page:
- Requires authentication
- Has **no visible username field**

…it may still be vulnerable.

### 🛠️ Try This:

1. **Look for hidden fields** containing the username. Modify it to target other accounts.

2. **Inject an additional username parameter** using the same key name as in the login form (e.g., `username=john`).
   - This may override the logged-in identity.
   - Can allow **privileged actions** on other users’ accounts.

---

## 🧵 Summary

| Weakness | Exploit Risk |
|----------|--------------|
| Unauthenticated access | Unrestricted password reset |
| Poor validation order | Brute-force old passwords silently |
| Verbose errors | Username enumeration |
| No rate limiting | Brute-force password guessing |
| Modifiable hidden username | Cross-account attacks |

---

Let me know when you’re ready to move to the next section: **Forgotten Password Functionality**.
