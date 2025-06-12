# Script-Based Validation


Because HTML's built-in validation (like `maxlength`, `required`, `type="email"`, etc.) is too simple for complex input needs, **web applications commonly implement custom client-side validation using JavaScript**.

For example, a product form might validate the `quantity` field to ensure it’s an integer between 1 and 50 using JavaScript before allowing submission:

```html
<form method="post" action="Shop.aspx?prod=2" onsubmit="return validateForm(this)">
  Product: Samsung Multiverse <br/>
  Price: 399 <br/>
  Quantity: <input type="text" name="quantity"> (Maximum quantity is 50)<br/>
  <input type="submit" value="Buy">
</form>

<script>
  function validateForm(theForm) {
    var isInteger = /^\d+$/;
    var valid = isInteger.test(quantity) && quantity > 0 && quantity <= 50;
    if (!valid)
      alert('Please enter a valid quantity');
    return valid;
  }
</script>
```

### How It Works

- The `onsubmit` attribute links the form to a validation function.
- If `validateForm()` returns `true`, the form is submitted; otherwise, it’s blocked.
- This gives developers flexibility to enforce custom validation logic on the client side.

---

## Bypassing JavaScript Validation

### Methods to Bypass

1. **Disable JavaScript in the browser**:
   - The `onsubmit` handler won't run at all.
   - Form submits without validation.

   **Drawback**: Some apps rely on JavaScript for rendering or functionality, which may break the page.

2. **Intercept and modify the validated request in a proxy**:
   - Enter a valid value (like `quantity=10`) in the browser.
   - Use Burp Suite to intercept and **change it to `quantity=500`** before it hits the server.

   **Advantage**: Keeps the app functional and circumvents validation elegantly.

3. **Modify the validation logic in the intercepted response**:
   - Change:
     ```javascript
     return valid;
     ```
     to:
     ```javascript
     return true;
     ```
   - This forces the browser to submit the form regardless of input.

---

## HACK STEPS

1. **Identify JavaScript-Based Validation**:
   - Look for scripts attached to form events (e.g. `onsubmit="..."`) or external JS files with validation logic.

2. **Bypass the Validation**:
   - Either:
     - Intercept the request and modify submitted values.
     - Modify the response to neutralize validation scripts.
     - Disable JS entirely (if the app works without it).

3. **Test Server-Side Replication**:
   - Submit invalid data.
   - If the server processes it without error, validation is **not replicated server-side** — this is a security issue.

4. **Test Fields Individually**:
   - Only test **one invalid input at a time**.
   - Submitting multiple invalid fields can prevent deeper validation logic from being executed.

---

## Key Notes

- **JavaScript validation alone is not a security control** — it improves usability, not security.
- The real risk exists **only if the server does not replicate** validation and **malicious input leads to dangerous behavior** (e.g. SQLi, XSS).
- Client-side validation is valuable for performance and UX — not for enforcing security.

--- 

