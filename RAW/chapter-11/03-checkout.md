## 🧠 Logic Flaw Example 3: Proceeding to Checkout 

---

### 🧩 Functionality: Normal Purchase Flow

Think of a typical online store (Amazon-style). The checkout process is meant to follow these **4 ordered steps**:

1. **Add to Cart**
2. **Review Cart & Finalize Order**
3. **Enter Payment Info**
4. **Enter Delivery Info**

The developer’s brain thinks:

> *“If the user reached step 4 (delivery), then of course they must have paid in step 3.”*

🔴 **WRONG.** That’s a dangerous assumption when the attacker **controls the flow.**

---

### 💥 The Flawed Assumption

> The app trusted the **user’s navigation flow** to enforce business rules.

But in reality:

* Users **can skip steps**.
* Users **can re-order steps**.
* Users **can directly hit any internal URL or endpoint**.

That’s called **forced browsing** — and it’s devastating when your backend doesn’t enforce **state consistency**.

---

### ⚔️ The Attack — Step-by-Step

#### 🧑 Attacker's Plan:

* Browse products (Step 1)
* Finalize order (Step 2)
* **SKIP payment (Step 3)** entirely
* Go straight to **delivery entry (Step 4)**

#### ✅ What happens:

If the backend logic doesn’t check:

* Whether payment was made,
* Or verify that the order is in a “paid” state…

➡️ The attacker **gets a confirmed order without paying.**
The order is shipped. The company loses money.

This is not just a business logic flaw — it’s **financial fraud** due to poor flow validation.

---

### 🔄 Real-World Analogy

Imagine this:

* A nightclub requires you to pay at the entrance (Step 1).
* Then gives you a wristband to get drinks inside (Step 2).
* But the bartender just checks for the wristband and assumes you paid.

Now, suppose the bouncer steps away — you just walk in through the side and go straight to the bar. You **never paid**, but you get the drinks.

That’s **forced browsing**.

---

## 🧰 HACK STEPS — How to Force Browse Like a Hacker

This is your offensive checklist when dealing with multistage flows like checkout, password reset, or account creation.

---

### 🔎 Step 1: Break the Expected Sequence

Try all of the following:

* Skip a step (e.g., go from step 1 to 4).
* Repeat a step.
* Go backwards (step 4 → 2).
* Replay a step with altered parameters.

You're not just submitting forms — you're probing **how state is tracked**.

---

### 🔎 Step 2: Understand the Flow Mechanism

Multistage flows can be handled in two ways:

* 🟢 **Different URLs** for each step (e.g., `/payment`, `/delivery`)
* 🔵 **Same URL** with different parameters or hidden fields (e.g., `/checkout?step=3`)

Your job is to:

* **Capture all requests (GET, POST)** using Burp or ZAP.
* **Map the flow**.
* Try to **inject or tamper with stage transitions** manually.

---

### 🔎 Step 3: Think Like the Developer (So You Can Break Their Assumptions)

Ask yourself:

* What **must** the developer be assuming about state?
* Are they **tracking payment status** in a server-side session?
* Or are they just trusting the frontend to lead the user through the right path?

If the app only checks:

> *“Oh, you're at delivery page, so you must have paid.”*

…you win.

---

### 🔎 Step 4: Watch for Broken States

When you mess with flow, the app might:

* Throw debug errors
* Leave variables uninitialized
* Process incomplete objects (e.g., shipping info with no billing info)
* Show strange or privileged behavior

This lets you dig deeper — or even craft a custom path through the app that bypasses security.

---

### ⚠️ BONUS TIP:

> This logic flaw is structurally **similar to access control vulnerabilities.**

For example:

* A user might only be allowed to **generate an invoice after payment.**
* But if the app allows **direct access to the invoice page** by skipping checks, that’s a privilege escalation.

This overlaps heavily with what you saw in **Chapter 8 (Access Control Flaws).**

---

## 🧠 Practice Questions (Example 3)

1. **What is forced browsing, and how does it differ from normal navigation?**
2. **Why is relying on frontend navigation logic risky in multistage processes?**
3. **What are two different technical ways an app might track checkout stages?**
4. **What are signs that the app might not be validating state transitions server-side?**
5. **Give a real-world scenario (outside of e-commerce) where skipping steps could lead to a logic flaw.**

---

## 🧪 Lab Setup Idea

Wanna build your own vulnerable flow?

1. Create a simple web app with:

   * Step 1: Add items
   * Step 2: Confirm order
   * Step 3: Payment
   * Step 4: Delivery Info

2. Use cookies or hidden fields to track progress (bad practice — intentionally weak).

3. Skip Step 3 and submit delivery in Step 4.

If the app proceeds with no server-side state checks…
➡️ You've built your own logic flaw lab.

---