## 🧠 Example 04: Rolling your Own insurance

The app is for **buying insurance online** and works like this:

1. You provide either your **desired monthly premium** or **coverage value**.
2. The app calculates the other value and gives you a quote.
3. You proceed through multiple steps entering personal info (health, hobbies, etc.).
4. The **underwriter** reviews your data and accepts or adjusts your application.

Pretty standard multi-step flow, right?

But **here's the fatal flaw**:

> **Every POST parameter from the user is blindly accepted and used to update the app’s internal state — regardless of what stage the user is at.**

This leads to **massive security issues**.

---

## 🧩 The Assumption

The devs assumed:

> “Users will only send parameters from the current form they're on.”
> e.g., Step 4 page only sends Step 4 data.

**WRONG.** This is a classic case of **trusting the UI instead of enforcing logic on the backend.**

Users can craft **custom POST requests** with **extra or fake parameters** from other steps — and the app just accepts and processes them.

---

## ⚔️ The Attacks (There Are 3)

Let’s unpack all 3 logic flaws that come from this single weak assumption.

---

### 🧨 1. **Bypassing Input Validation**

* Each step performs **strict validation** of the data expected **at that step**.
* But if you submit a **field from a *different* step**, it’s not expected — so **no validation is done**.

#### 🔥 Exploit:

* In Step 6, you inject `hobbies=<script>alert('XSS')</script>`
* That parameter was meant for Step 3 — no validation is triggered.
* It gets stored and **executed in the underwriter's browser later.**

🎯 **Stored XSS on the backend staff.**

---

### 🧨 2. **Tampering Insurance Quote**

At Step 1:

* You choose **either**:

  * Monthly premium (`premium=1000`)
  * OR insurance value (`cover=50000`)
* The app calculates the other value using internal logic.

But…

#### 🔥 Exploit:

* You go to Step 8 (way later), but **inject** new values:

  ```
  premium=10
  cover=1000000
  ```

* The backend updates its state with **whatever you send** — even if you’re not supposed to be modifying these anymore.

🎯 **You can buy \$1M insurance for \$10/month.**

---

### 🧨 3. **User Impersonating an Underwriter**

The underwriter uses the **same system** to:

* Accept or reject applications
* Adjust quotes or change sensitive fields

But...

There’s **no access control on who can send which parameters.**

#### 🔥 Exploit:

* You guess (or observe) the field names the underwriter uses:

  ```
  acceptApplication=true
  underwriterComments="Looks good"
  ```
* Then submit them **as a regular user** during your next POST request.

Result?

🎯 **You accept your own application** — no underwriter needed.

---

## 🔍 TL;DR – What Went Wrong?

| Flaw                             | Description                                                | Exploit                                  |
| -------------------------------- | ---------------------------------------------------------- | ---------------------------------------- |
| 🔄 Out-of-sequence data          | App updates state with data from any stage                 | Skip validation, inject arbitrary values |
| 🔓 Unrestricted field acceptance | App doesn’t check which fields a user is allowed to submit | Accept your own insurance, modify price  |
| 👥 Role confusion                | Underwriter and user use same processing logic             | User impersonates underwriter            |

---

## 🧰 HACK STEPS – Real Pentester Checklist

Here’s how you weaponize this in testing:

---

### 🔎 Step 1: Parameter Smuggling Across Stages

* Capture parameters submitted in each stage (Step 1 to N).
* At each stage:

  * Inject parameters from other steps (especially earlier ones).
  * Watch what the app silently accepts or stores.

🎯 Look for inconsistent state, lack of validation, or weird app behavior.

---

### 🔎 Step 2: Role Parameter Injection

* Observe what parameters a **privileged user (admin, underwriter, etc.)** sends.
* Try sending the same parameters **as a regular user**.
* If the app **doesn’t check your role server-side**, you’ll be able to perform privileged actions.

🎯 Look for:

* Role elevation
* Approval bypasses
* Data leakage or manipulation

---

## 🔐 How Should This Be Fixed?

A properly designed backend should:

1. **Whitelist fields per step** – Only allow parameters from the current stage.
2. **Enforce validation** on **every field**, regardless of how it’s submitted.
3. **Enforce role-based parameter handling** – don’t let users submit underwriter-only fields.
4. **Use internal flags/state machines** to track progress, not rely on user input.

---

## 🧠 Practice Questions

1. Why is it dangerous for the server to blindly accept all POST parameters?
2. How can submitting out-of-sequence parameters bypass validation?
3. How can a user impersonate an underwriter in this context?
4. What should the server do to prevent this kind of logic flaw?
5. How would you test a multi-step workflow to find parameter-based logic flaws?

---

## 🧪 Lab Setup Idea

Create a Flask or Node.js app with:

* 3-step insurance form.
* Fields stored in a global session object.
* Accept all POST data as `session.update(request.POST)`.

Then:

* On step 3, inject a step-1 field like `premium=5`.
* Accept your own app as a "user" by submitting `decision=accept`.

You’ll reproduce the exact same logic flaw.

