# Capturing User Data: HTML Forms


Another common way client-side controls are used is through **HTML forms**, which gather input from the user and submit it to the server. While client-side validation (e.g. `maxlength`, input types, or JavaScript checks) can guide the user, **relying on these validations as security mechanisms is dangerous** — they can be trivially bypassed.

## HTML Forms as a Data Capture Mechanism

HTML forms submit user input as **name/value pairs**. Example:

```html
<form method="post" action="Shop.aspx?prod=1">
  Product: iPhone 5 <br/>
  Price: 449 <br/>
  Quantity: <input type="text" name="quantity" maxlength="1"> <br/>
  <input type="hidden" name="price" value="449">
  <input type="submit" value="Buy">
</form>
```

### Issue: `maxlength` Client-Side Enforcement

- The `maxlength="1"` attribute restricts users from typing more than one character (i.e. a value < 10).
- Server might assume that only single-digit quantities will be received.
- **Bypassing this is trivial**:
  - Intercept and modify the form before it renders (remove the `maxlength`).
  - Intercept the request after form submission and modify the `quantity` parameter.

## Intercepting Cached Responses

You may want to intercept and modify the original HTML or JavaScript served by the application. But sometimes your proxy (e.g., Burp) may show this response:

```http
HTTP/1.1 304 Not Modified
Date: Wed, 6 Jul 2011 22:40:20 GMT
Etag: "6c7-5fcc0900"
Cache-Control: max-age=7200
```

This means the browser is **loading the content from cache** and not from the server.

### What’s Happening?

- The browser sends headers like:
  ```http
  If-Modified-Since: Sat, 7 Jul 2011 19:48:20 GMT
  If-None-Match: "6c7-5fcc0900"
  ```
- If the server determines the cached version is still valid, it sends `304 Not Modified` and doesn't resend the full content.

### How to Force the Server to Send the Full Response

- **Intercept the request** and **remove** these two headers:  
  `If-Modified-Since`, `If-None-Match`
- The server will now return the **full updated resource**.
- **Burp Suite** has a setting to strip these headers automatically from all requests.

## HACK STEPS

1. **Locate `maxlength` Attributes**:
   - Search HTML forms for input fields with `maxlength`.

2. **Submit Overlong Values**:
   - Send a longer value (e.g., `quantity=999`) while preserving proper format (e.g., numeric if required).

3. **Check Application Response**:
   - If the server accepts the overlong input and processes it, server-side validation is missing.

4. **Leverage Lack of Validation**:
   - Try exploiting vulnerabilities like:
     - **SQL Injection** (e.g., longer string inputs)
     - **XSS** (e.g., script in text fields)
     - **Buffer Overflow** (for native components)
