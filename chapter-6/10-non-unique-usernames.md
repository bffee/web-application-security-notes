# Nonunique Usernames

In rare cases, web applications allow users to **self-register with nonunique usernames**, meaning multiple accounts can exist with the same username. This represents a serious **design flaw** with multiple security implications.

---

## Why This Is a Problem

### 1. Credential Collision
- If two users have the same username and choose the **same password**, several issues may arise:
  - The application might **reject the second user’s password**, inadvertently disclosing that those credentials are already in use.
  - Worse, the application might **allow identical credentials** for different accounts, and subsequent logins will result in one user **accessing another's account**.

### 2. Brute-Force Bypass
- Even if the main login form implements protections like **account lockout or rate limiting**, an attacker may exploit registration to bypass these protections:
  - By registering the same **target username repeatedly** with different passwords.
  - Monitoring application responses for **differential behavior** (e.g., password rejection due to existing match) allows the attacker to infer the **correct password** without logging in.

---

## Related Vulnerability: Username Enumeration via Registration

- If the application **disallows duplicate usernames**, an attacker can exploit this to **enumerate valid usernames**:
  - Attempt registration using a list of **common usernames**.
  - Any username that is **rejected as "already in use"** is confirmed as valid.

---

## HACK STEPS

1. **Test for duplicate registration**:
   - Attempt to register the **same username twice**, using **different passwords**.

2. **If duplicate usernames are rejected**:
   - Use the registration page to **enumerate valid usernames**.
   - Submit registration requests with **common usernames** and record which ones the application blocks.

3. **If duplicate usernames are allowed**:
   - Register the same username **twice** with the **same password**.
   - Observe the behavior:
     - Does the application display an **error message**?
     - Can you **log in** and access different user accounts?

   #### a. Application returns an error:
   - Use this behavior to conduct a **stealth brute-force attack**:
     - Target a known or guessed username.
     - Attempt to register it repeatedly with different passwords.
     - If a password is **rejected**, it likely **already belongs to an existing account**.

   #### b. Application allows identical credentials:
   - Log in with the registered username and password.
   - Modify the data in each account to determine:
     - Whether accounts are **merged**, or
     - You can **access data from other users**, indicating a full authentication bypass.

---

## TIP

Even though nonunique usernames are rare, always test self-registration thoroughly. It may be the **only location** in the application where username enumeration or credential probing is possible without triggering **login protections** or raising alarms.

---

## Summary Table

| Vulnerability Type         | Description                                                                 | Exploitable For                |
|----------------------------|-----------------------------------------------------------------------------|--------------------------------|
| Credential collision       | Same username + password leads to account confusion or disclosure          | Unauthorized access            |
| Brute-force via registration | Bypass login limits by brute-forcing through repeated registration attempts | Password discovery             |
| Username enumeration       | Rejected registration confirms username already exists                     | User identification/enumeration|
