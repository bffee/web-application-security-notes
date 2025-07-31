## 🧠 **Example 2: Fooling a Password Change Function** — Explained

---

### 🎯 Core Idea:

The app assumes:

> **If the `existingPassword` parameter is missing, this must be an admin.**

That’s not just naïve — that’s security by **UI**, not by logic.

---

### ⚙️ Application Logic Breakdown

The app has two user types:

1. **Ordinary user**: Can change *their own* password, but must enter the current password.
2. **Admin**: Can change *anyone’s* password, no need to verify existing one.

Both features are handled by the **same server-side script**.

---

### 🔐 The Server-Side Logic (Simplified):

```java
String existingPassword = request.getParameter("existingPassword");

if (existingPassword == null) {
    // Must be an admin!
    changePasswordWithoutValidation();
} else {
    // Must be a user — validate the old password
    validateOldPassword();
}
```

This code literally says:

> *If `existingPassword` is missing — congrats, you’re an admin.*

---

### ⚔️ The Attack — Step-by-Step

Let’s say you’re just a regular user. Here’s how you can break in:

#### ✅ Legit request:

```http
POST /changePassword
username=alice
existingPassword=correctpassword
newPassword=hacked123
```

✔️ Server checks the old password.
✔️ You can change your own password.

---

#### 🔥 The attack:

```http
POST /changePassword
username=admin
newPassword=hackedRoot
```

* You **omit** the `existingPassword` field entirely.
* Server thinks:

  > “No old password? This must be an admin request!”
* ✔️ Password for the **admin** gets changed.
* 🎉 You now control the admin account.

This is **critical severity** — one request, full compromise.

---

## 🚩 Why This Happened

1. **Trusting the client UI**: The browser form didn’t show the `existingPassword` field for admins.

   > But a hacker isn’t using your form — they’re crafting raw requests.

2. **Bad indicator**: The server determines user role based on the **presence of a parameter**.

   > That’s like deciding someone’s a cop just because they didn’t ask for permission.

3. **No role-based access check**: The server should **verify the user’s role on the backend**, not infer it from request structure.

---

## 🧰 HACK STEPS — What to Try on Real Targets

When you’re testing any logic (like password changes, profile updates, etc.), do this:

---

### 🔍 Step 1: Strip Parameters One at a Time

* Remove **one parameter completely** — **not just its value**, remove its name too.
* Why? Some servers treat `existingPassword=` (empty) differently than **no field at all**.

---

### 🔍 Step 2: Track How the App Reacts

* Watch for:

  * Skipped validation
  * Changes in flow
  * Access to restricted functions
  * Silent successes

---

### 🔍 Step 3: Follow Through

* Don’t just test request A.
* See what happens in request B, C… if it's a multi-step process, the logic may defer checks until later.

  E.g., changing an email in step 1 might silently update the account owner in step 3.

---

### 🛠️ Example Tools:

* **Burp Suite** — Use Repeater to remove fields and replay requests.
* **ZAP** — Fuzz parameters, strip fields, analyze flows.

---

## 🧠 Practice Questions (Example 2)

1. **Why is it dangerous to determine user roles based on form field presence?**
2. **What’s the key difference between submitting an empty field and omitting the field entirely?**
3. **What assumption did the developer make that led to this flaw?**
4. **If you find a password reset endpoint with no old password required, what checks would you perform before exploiting it?**
5. **What security control should have been used instead of relying on the `existingPassword` field?**

---

## 🧪 Lab Setup Idea

Want to recreate this flaw locally?

Build a small login system in Flask or Node.js:

* Route: `/change-password`
* Accepts: `username`, `existingPassword`, `newPassword`
* If `existingPassword` is missing, allow password change without validation
* Store user sessions with roles (`admin`, `user`) and **intentionally don’t check them**

Then try removing `existingPassword` and see if it lets you change anyone’s password.

---
