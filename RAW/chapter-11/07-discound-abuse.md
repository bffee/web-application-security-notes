## Example-07: Discount Logic Abuse via Cart Manipulation

This isn’t about breaking the app’s security — it’s about **tricking its brain** into giving you what you don’t deserve.

---

### 💡 The Scenario (Retail App Logic)

* You’re in a **software store** (think: antivirus, antispam, firewall apps).
* There’s a **bulk discount rule**:

  * If you buy **certain combinations** (e.g., antivirus + firewall + antispam), you get **25% off** the price of each item.
* Sounds fair… until it isn’t.

---

### 🧠 The Developer Assumption

> *“Once the discount is calculated and applied, the user will check out the full bundle.”*

They assume the user behaves like this:

1. Adds the full bundle.
2. Gets discount applied.
3. Proceeds directly to checkout.
4. Profit.

### ❌ The Real User Behavior (The Attack)

But a malicious user does this instead:

1. Adds **everything** to the cart → triggers **max discount** logic.
2. Discount gets calculated and applied to every item.
3. Starts **removing items** they don’t want.
4. Ends up paying **way less** for a single product that no longer qualifies for any bundle discount.

💸 **Result**: They pay \$20 for antivirus instead of \$30 — because the system *thinks* the user still has a full bundle.

---

## 🎯 Key Flaw: One-Time Discount Evaluation

* The application calculates and **applies discounts early**.
* It doesn’t **re-evaluate the cart** when items are removed.
* No rollback logic = persistent unauthorized benefit.

---

## 🧪 HTB-Style Exploitation Mindset

### ✅ Hack Steps:

| Step | Action                                                                                                                  |
| ---- | ----------------------------------------------------------------------------------------------------------------------- |
| 1.   | Add **all combo-required items** to the cart to activate discounts.                                                     |
| 2.   | Intercept or monitor the moment when **discount is applied** — find if it's client-side (JS) or server-side (response). |
| 3.   | After discount is applied, **remove one or more items** that triggered the discount.                                    |
| 4.   | Check if discount **remains** on the items you're keeping.                                                              |
| 5.   | Try variations: remove mid-checkout, remove then undo, manipulate request params, etc.                                  |

---

### 🧠 Creative Variants You Can Try

| Manipulation                       | Goal                                 |
| ---------------------------------- | ------------------------------------ |
| Add, remove, and re-add items      | Trick app into recalculating wrongly |
| Add duplicate items                | Inflate quantity threshold           |
| Use multiple browser tabs          | Cross-tab sync confusion             |
| Modify hidden cart params via Burp | Fake quantities/prices               |

---

## 🧱 Developer Defense Strategy

To **fix** this kind of logic flaw, apps must:

* 🔄 **Recalculate discounts** every time cart contents change.
* ✅ Apply discounts **only at checkout confirmation**, not earlier.
* 🔒 Store **discount logic server-side**, not in client-visible scripts.
* 🧪 Include logic test cases like:

  > “What happens if a user qualifies for a discount, then removes qualifying items?”

---

### 🧩 Real-World Examples of Similar Issues

| App Type             | Exploit Path                                                     |
| -------------------- | ---------------------------------------------------------------- |
| Airline Booking      | Add refundable items → get discount → cancel refundables         |
| Subscription Bundles | Add multiple services for discount → remove some before checkout |
| SaaS Platform        | Add premium tier → get perk → downgrade to free, keep perk       |

---

## 🧠 Red Team Mentality

When you see **discounts, bundles, or tier-based rewards**, ask:

> What if I:
>
> * Add items just to trigger benefits?
> * Remove them right after?
> * Replay the discount token in a new session?

You're not attacking the system — you're **beating the logic that runs it**.

