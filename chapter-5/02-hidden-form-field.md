# Hidden Form Fields

Hidden HTML form fields are often used to store data that applications assume users cannot change. While not visible in the browser’s rendered view, these fields are fully accessible and editable by the user because they reside in the page source and are submitted with the form.

### Mechanism:

* Hidden fields are declared with `<input type="hidden">` in HTML.
* Their values are submitted along with user-entered data in POST/GET requests.
* Example usage in e-commerce: storing the product price or ID in hidden fields.

## Vulnerability Example:

```html
<form method="post" action="Shop.aspx?prod=1">
  Product: iPhone 5 <br/>
  Price: 449 <br/>
  Quantity: <input type="text" name="quantity"> (Maximum quantity is 50) <br/>
  <input type="hidden" name="price" value="449">
  <input type="submit" value="Buy">
</form>
```

On form submission:

```
POST /shop/28/Shop.aspx?prod=1 HTTP/1.1
Host: mdsec.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 20

quantity=1&price=449
```

## Attack Techniques:

1. **Manual HTML Editing:**

   * Save the HTML source, edit the hidden field’s value.
   * Load the modified file in a browser and submit the form.

2. **Intercepting Proxy (e.g., Burp Suite):**

   * Proxy captures and allows modification of HTTP/HTTPS requests.
   * Modify hidden field value in-flight (e.g., change price).
   * No need to edit the source manually.

## Tool Usage:

* Burp Suite is highlighted as the key tool for this task.
* Intercepts requests and responses.
* Enables modification before data reaches the server.

## Advanced Attack Tip:

* Try submitting **negative values** in price fields.
* Some flawed applications process negative prices and issue refunds along with item delivery (negative transaction attack).

## Key Takeaway:

Client-side hiding does **not** equate to security. Any data sent to the client can be intercepted and modified, making hidden fields a frequent cause of critical vulnerabilities.

## Defense Recommendation (implied):

* Never trust client-side data.
* Always validate and enforce business logic (e.g., pricing, product ID) on the server side.
