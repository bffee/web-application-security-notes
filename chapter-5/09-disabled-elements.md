# Disabled Elements


In HTML, form elements with the `disabled` attribute:
- **Appear grayed out** to the user.
- **Cannot be interacted with** in the browser UI.
- **Are not included in the form submission** sent to the server.

### Example

```html
<form method="post" action="Shop.aspx?prod=5">
  Product: Blackberry Rude <br/>
  Price: <input type="text" disabled="true" name="price" value="299"><br/>
  Quantity: <input type="text" name="quantity"> (Maximum quantity is 50)<br/>
  <input type="submit" value="Buy">
</form>
```

**Browser behavior**: Only the `quantity` field is submitted, **not** the `price` field.

---

## Security Implication

The presence of a disabled input like `price` can suggest:
- The server might still **accept and process** the `price` parameter **if submitted manually**.
- This can happen when the field was used earlier (e.g. during development/testing), and the backend logic was not properly updated.

### Potential Exploit

If the server does still honor the `price` field:
- You can manually add the `price` parameter back during interception:
  ```http
  POST /Shop.aspx?prod=5
  ...
  price=9&quantity=1
  ```
- If not validated server-side, the product could be purchased at a **lower price**.

---


## HACK STEPS

1. **Identify Disabled Elements**:
   - Manually inspect the page **source** or use your proxy to analyze the server responses.
   - Browsers **exclude disabled elements from requests**, so passive monitoring won't detect them.

2. **Submit Disabled Parameters Manually**:
   - Add them in Burp Repeater or through request tampering.
   - Observe if the server processes them (e.g., does it accept and honor a modified price?).

3. **Test Disabled Submit Buttons**:
   - If buttons like `submit`, `delete`, or `update` are disabled conditionally:
     - Manually submit the form with that button’s `name=value`.
     - Check whether the server accepts and performs the action.
     - Example:
       ```http
       ...&submit=delete
       ```

4. **Automate Re-enabling via Burp**:
   - Use **Burp Proxy > Match and Replace** or **Burp's HTML modification feature** to:
     - Strip `disabled="true"` from inputs.
     - Modify DOM in transit so that all fields are enabled client-side.

---

## Key Notes

- **Disabled ≠ Secure**: Just because a field is disabled doesn’t mean it’s inaccessible to an attacker.
- **Manual Testing is Crucial**: Since browsers ignore disabled fields in submission, **you must deliberately test them**.
- **Common Targets**:
  - Price fields
  - Hidden functionality (discount codes, administrative options)
  - Grayed-out buttons

---

✅ **Actionable Tip**: Always test disabled fields by **forcibly including them** in the request. If the server fails to verify their legitimacy, **business logic flaws** or **privilege escalation** may be possible.
