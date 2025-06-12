# Handling Client-Side Data Securely

## Core Problem

All client-side data and logic are inherently **untrusted**:
- The **browser** is under the user's control.
- Any data received from the client could be **malicious** or **tampered with**.
- Thus, **server-side validation and logic must always assume the worst**.

---

## Transmitting Data Via the Client

Many vulnerable applications transmit sensitive data (like **product prices**, **discounts**, etc.) through the client. This is insecure because:
- Users can **view, modify, and replay** the data.
- There’s often **no reason** to do this; the server usually has all the info it needs.

### ✅ **Best Practice**

Let the client submit **only identifiers** (e.g., `product_id`, `quantity`), and let the **server look up all relevant values** (e.g., price, discounts).

**Correct model:**
```http
POST /checkout
product_id=123
quantity=2
```

Server:
- Looks up the product in DB
- Looks up user-specific discounts
- Calculates price internally
- Never trusts client-submitted price

---

## If You Must Transmit Critical Data

If your application **must** send sensitive data to the client (e.g., price), use **cryptographic protections**:

### 1. **Signing/Encrypting** Critical Data

Store sensitive data in the client using encryption or digital signatures.

**BUT: Beware of these common flaws:**

#### ❌ Replay Attacks
- If the same encrypted string (e.g., price for Product A) is reused for Product B, attackers can swap them.
- **Fix**: Bind encrypted values to their context.
  - For example: encrypt `product_id=123&price=399` together.
  - Then validate that the `product_id` and `price` in the encrypted blob **match** the form values.

#### ❌ Known Plaintext Attacks
- If users know both the plaintext and ciphertext of some values, they might reverse-engineer the encryption key.
- This is especially dangerous if symmetric encryption is used carelessly.

---

## ASP.NET-Specific Advice

- Do **not** store custom or sensitive data in ViewState.
- If you must, **enable ViewState MAC** to ensure integrity.
- ViewState MAC ensures that the server will reject tampered ViewState data.

---

## Validating Client-Generated Data

Client-side validation **improves user experience** but is never enough for security.

### Why Client-Side Validation Can Be Bypassed

- HTML form restrictions (e.g., input type, maxlength) are easy to override.
- JavaScript checks can be bypassed by:
  - Disabling JavaScript
  - Modifying scripts
  - Intercepting and changing requests

Even complex controls like browser extensions or obfuscated code can be reverse-engineered.

---

## ✅ Only Trust Server-Side Validation

Treat **all client input** as **untrusted**, regardless of:
- How it was generated
- Any validation already done in the browser
- Whether it’s from HTML, JS, extensions, or mobile apps

---

## Common Misconception

> “Client-side controls are inherently bad.”

Not always true. It depends on how they're used.

### ✔ Acceptable Uses of Client-Side Controls:

- **Usability improvements**:
  - Format validation (e.g., email, phone, DOB)
  - Required field checks
  - Preventing invalid form submissions to reduce server load
- **Defensive scripting**:
  - Preventing DOM-based XSS before data hits the browser
  - Filtering malicious data in JavaScript **before rendering**, even if the data came from the server

BUT — the server **must still validate** everything before processing it.

---

## Final Word

| Client-Side Role | Secure? | Comments |
|------------------|---------|----------|
| Input validation | 🚫      | Can be bypassed |
| Obfuscation      | 🚫      | Only slows down attackers |
| Data encryption  | ✅*     | Must prevent replay, and avoid key exposure |
| Server validation| ✅✅✅  | Only real defense |

🔒 **Never trust the client.**
