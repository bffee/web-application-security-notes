## 🔎 Example-06: Business Logic Abuse via Numeric Manipulation

This flaw isn’t a code injection or privilege escalation — it’s a **subtle logic bypass** using *math itself* as the weapon.

---

### 💡 The Scenario (The Setup)

* It’s an **ERP system** used by a **manufacturing company**.
* Finance personnel can initiate **fund transfers** between:

  * Company accounts
  * Key customer/supplier accounts

✅ Makes sense — maybe moving money for payments, invoices, etc.

---

### 🔐 The Business Rule

> ❗ To **prevent fraud**, there's a control:

* Transfers **above \$10,000** require **senior manager approval**.

That’s a **hard-coded threshold** like:

```cpp
bool CAuthCheck::RequiresApproval(int amount) {
    if (amount <= m_apprThreshold)
        return false;
    else
        return true;
}
```

They assume:

> If the transfer is ≤ \$10,000 → ✅ Auto-approved
> If > \$10,000 → 🔒 Requires secondary approval

So far, it *looks secure*… until you realize:

---

### 💣 The Logic Flaw

> ❗ The check only filters for **amounts over \$10,000**.
> It doesn’t filter for **negative amounts**.

And here's where it explodes:

* Backend accepts **negative transfers**.
* Logic in backend treats a `-20,000` transfer from B → A as:

  > "Just send \$20,000 from A → B" — the reverse operation.

#### 💥 The Bypass:

User wants to transfer \$20,000 from A to B:

* Can’t send `+20000` → gets blocked for approval.
* So they submit: `amount = -20000`, **but swap the source/destination accounts**.

Now:

* ✅ Transfer is **under the threshold** (since `-20000 < 10000`)
* ✅ It gets auto-approved
* ✅ \$20,000 moves from A to B anyway
* ❌ But **without senior manager approval**

---

## 🧠 Why This Happened

The flaw boils down to **two incorrect assumptions**:

1. Developers trusted that checking `amount <= threshold` is enough.
2. They didn’t validate **transfer directionality + signs** at all.

The business rule enforced the **value** of the transaction, but didn’t account for **how the application interprets that value in terms of source/destination logic.**

---

## 🧪 HTB-Style Exploitation Mindset

### ✅ Hack Steps:

| Step | Action                                                                                                   |
| ---- | -------------------------------------------------------------------------------------------------------- |
| 1.   | Find any field that controls a **numeric business rule** (amounts, limits, thresholds)                   |
| 2.   | Try inserting **negative numbers**, decimals, or manipulated data (like `999999999` or `0x3E8`)          |
| 3.   | Observe if app accepts/executes the action, or gives errors                                              |
| 4.   | Abuse negative values to **reverse flow**, **gain unauthorized benefits**, or **bypass approval layers** |
| 5.   | Repeat with larger numbers and different accounts to craft an actual exploit chain                       |

---

## 🧩 Other Real-World Examples of Similar Flaws

| App Type     | Example Business Limit Abuse                               |
| ------------ | ---------------------------------------------------------- |
| Retail       | Buy items using **negative quantity** to get refund/credit |
| Bank         | Send bill payment of `-9999` to credit own account         |
| Insurance    | Submit negative age to get ultra-low premium               |
| Subscription | Set usage counter to `-1` to avoid hitting quota           |

---

## 🧱 Defense Strategy (Fixing the Root)

> Business logic validation needs to account for **more than just a numeric value check**.

### ✅ Best Practices:

* 🔒 Disallow negative values **where they don't make sense**.
* 🔁 Match the logic of amount + direction:

  * If `fromAccount` and `toAccount` are present → check consistency.
* 💼 Enforce limits on the **absolute value** of a transaction.
* ⚠️ Backend should never blindly assume "less than \$10K = safe".

---

## 🧠 Red Team Mindset Boost

When you’re in a black-box test and see **any number-related input**, ask:

> * What happens if I go negative?
> * What happens if I repeat the operation?
> * Can I invert this flow or abuse rounding?

Because **math is the most under-tested and over-trusted part** of most web apps.

---