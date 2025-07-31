## Example 05: Braking the Bank

This is about an online banking application that allows **existing customers** (who don't yet have online access) to **register for it**.

Here’s how it works:

1. Customer enters **non-secret personal info** (like name, DOB, address).
2. App validates the info → forwards it to backend.
3. A **physical info pack** is mailed (includes a one-time password).
4. Customer calls a call center to activate the account.

🔐 **Security appears strong**, because:

* It uses some personal info.
* It sends a secret (OTP) via physical mail (out-of-band).
* It requires phone-based identity verification.

BUT…

💣 **All of this was sabotaged by one simple logic flaw:**

> **They reused a shared backend object (`CCustomer`) in the wrong context.**

---

## 🔧 The Assumption

> "We can use this CCustomer object in the registration flow — it's just a harmless data holder."

❌ **WRONG**.

That object is **also used after login**, and it defines **who the logged-in user is** — it contains:

* Customer number
* Personal info
* Session state
* Access decisions

So when an attacker uses the registration process inside an authenticated session...
➡️ The **current session’s `CCustomer` object gets overwritten** with data of a *different customer*.

---

## ⚔️ The Exploit — Session Identity Hijack

Here’s how the attacker breaks the bank:

### 1. 🔐 Login normally

* Attacker logs into their own real account.
* This sets their session and assigns a `CCustomer` object to them.

### 2. 🧪 Go to the registration flow (meant for new users)

* Attacker fills out the form, but instead of their own info, they provide someone else’s valid personal info.

> **Result:**
> The application **replaces the session’s current `CCustomer` object** with a new one — pointing to the victim’s customer number.

### 3. 🚨 Access privileged account data

* Now, attacker clicks on “My Account,” and guess what?
* The app pulls data for the *victim* — based on the overwritten `CCustomer` object.

🎯 Boom. Attacker is now impersonating the victim **without credentials**.

---

## 🧱 Root Cause: Broken Identity Management

This wasn’t a bug in the registration flow **alone** — it was a flaw in how **identity is handled across the app**.

* Identity = customer number in a shared object
* That object can be **repopulated mid-session**
* Access control and data rendering all use that object blindly

---

## 🚩 Why This Flaw Was So Dangerous

| Factor                                        | Risk                                       |
| --------------------------------------------- | ------------------------------------------ |
| Shared component reused across modules        | 🛑 Opens up unintended attack paths        |
| Session state overwritten post-login          | 🔥 Identity swap without re-authentication |
| Assumption that registration == pre-auth only | ❌ Didn’t expect logged-in users to hit it  |
| Role/Access control based on mutable object   | 💣 Vulnerable to business logic attacks    |

---

## 🧰 HACK STEPS – How to Spot This in Real Apps

This is an **application-wide design flaw**, not a simple input validation issue. So how do you spot it?

### 1. 🎯 Check if session state can change across flows

* Login as user A
* Visit any other flow (registration, apply for loan, edit profile)
* Inject user B's data
* See if the session now “thinks” you’re user B

### 2. 🔄 Switch context mid-session

* Start one action (registration, password reset)
* Complete it with someone else's data
* See if that changes who you're impersonating in the current session

### 3. 🔍 Look for shared objects or data holders like:

```java
session.setAttribute("currentCustomer", new Customer(...));
```

This is a red flag unless that object is **locked down** and validated on every step.

---

## 🧠 Summary — What You Should Learn

| Concept                                 | What You Should Remember                                                         |
| --------------------------------------- | -------------------------------------------------------------------------------- |
| 🧩 Component reuse                      | Never assume a data structure used in one module is safe in another context      |
| 🧠 Identity must be immutable           | Once a session starts, user identity should never change unless re-authenticated |
| 🔍 Registration isn't always public     | Logged-in users hitting "public" flows can break logic assumptions               |
| 💀 Access control isn't just role-based | It also depends on session integrity and identity linkage                        |

---

## 🧪 Practice Questions

1. Why is it dangerous to let a logged-in user access a public registration flow?
2. What is the risk of using the same object for both session identity and form processing?
3. How could you test whether a session’s identity can be overwritten?
4. How should identity and access control be implemented to avoid this type of flaw?
5. What are some red flags in a backend codebase that could suggest this flaw exists?

---

## 🔐 How to Fix It

1. **Separate data models**: Use different classes/objects for registration vs. logged-in identity.
2. **Immutable session identity**: Once a user logs in, their `customerNumber` in session should **never be replaced**.
3. **Add backend flags**: Session state should track if user is in "registration mode" vs "authenticated mode".
4. **Enforce user consistency**: Backend should verify that any form submissions relate to the currently authenticated user.

---

Excellent observation, and you’ve hit on the *exact* point where most people get confused with this kind of logic flaw. This isn’t your typical authentication bypass — it’s **session corruption via state injection**. Let’s break it down cleanly and explain **how and why the backend behaves this way**, step by step.

---

### 🧠 First, Clarify the Flow

Let’s repeat what the app **is supposed to do**:

#### ✅ Registration Process (For *existing* bank customers who want online access):

* You’re **already a customer** (maybe from physical banking), but **don’t yet use online banking**.
* You go to the online portal → enter personal data like:

  * Name
  * Address
  * Date of Birth
* **No password or PIN is entered at this point.**
* App **verifies** if this info matches an existing customer.
* If yes → it sends a mail to the registered address with:

  * A **one-time password**
  * Instructions for **activating online access** via phone.

So, it’s **not a public sign-up**, it’s like saying:

> “I already have a bank account, let me claim it for online banking.”

---

### ❗ Where the Problem Starts

#### The key backend mistake:

They used this object in both the registration and core app:

```java
class CCustomer {
  String firstName;
  String lastName;
  CDoB dob;
  CAddress homeAddress;
  long custNumber;
  ...
}
```

When **anyone submits info in the registration form**, the backend:

1. Looks up the customer by the provided info.
2. Finds that this is an *existing* customer.
3. Updates the `CCustomer` object in the **current session** with that customer’s info.

🧨 But… if the user is already logged in, their session already contains a `CCustomer` object pointing to **their own identity**.

➡️ By submitting the registration form with someone else’s info, the attacker causes the backend to **overwrite the current session’s customer object** with **someone else’s**.

---

### 🔓 So What Does This Actually Mean?

Let’s walk through the attack with real-world-style reasoning:

#### Step-by-Step Attack

1. 🔐 **Attacker logs into their own account** — full authentication happens.

   * Session is created.
   * Backend stores: `session.customerNumber = 1337`

2. 📝 Attacker goes to the **registration form** (meant for existing customers).

   * Provides name, DOB, and address of **victim** (say `Alice`, customer #1338).
   * This form is **available to the attacker**, even though they’re logged in.
   * Backend:

     * Looks up Alice in database.
     * Finds match → updates `session.customerNumber = 1338`
     * Overwrites the original session identity.

3. 💥 Now, attacker visits `/myAccount`.

   * The backend uses `session.customerNumber` to pull account info.
   * Shows **Alice’s account** to attacker.

No re-authentication, no OTP — just a poisoned session.

---

### 🔍 Why Didn’t the App Block This?

Because of these flawed assumptions:

| Assumption                                                | Reality                                                       |
| --------------------------------------------------------- | ------------------------------------------------------------- |
| Only unauthenticated users will use the registration form | Wrong — authenticated users can access it too.                |
| Overwriting the session object is harmless                | Wrong — this object defines who the user *is*.                |
| Users can't submit data for someone else                  | Wrong — many public data leaks expose names, DOBs, addresses. |

---

### ⚠️ Now Answering Your Specific Confusions

> **“Isn’t registration supposed to reject already existing customers?”**

No. This flow is **for existing customers** to **register for online banking**. So finding a match in the DB means the user is eligible — not an error. That’s why it doesn’t redirect or block.

---

> **“How does providing someone else's info even work?”**

Because the backend logic is:

```java
if (name + dob + address matches someone in DB)
   return their customerNumber
   overwrite session.CCustomer
```

The attacker isn’t creating a new user or logging in — they’re just tricking the system into replacing the session identity.

---

> **“Why isn’t the backend stopping this?”**

Because it reuses the same object (`CCustomer`) across multiple modules:

* Used in registration
* Used in post-login sessions
* Used in core account access

But it **doesn’t isolate session roles** or restrict this logic based on user state (logged-in vs not).

---

### 🧠 Final Analogy

Think of it like this:

You log into your real bank account → session knows it’s you (`User #1`).
Then you go to a “claim your account” form and submit someone else's details (`User #2`).
The app updates your session to now think you’re `User #2`.
You’re **not actually logged in as them** — but the app has no idea anymore, because your session now references `User #2`'s identity.

➡️ The session is corrupted.

---

### ✅ Key Takeaways

* **This isn’t a login bypass** — it's **session state corruption** by abusing a registration flow.
* Never assume only unauthenticated users will access certain pages.
* Never allow identity-related session objects to be overwritten **after login**.
* Reusing data objects across contexts = **exploit surface**.

---
