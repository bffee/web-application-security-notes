# Opaque Data

Sometimes, web applications transmit **non-transparent (opaque) data** via the client that isn't immediately readable. This data is often **encrypted or obfuscated**, hiding its plaintext meaning. While this may seem like a secure method of data handling, it still relies on client-side transmission and is subject to tampering.

### Example

Consider a form used to purchase a product:

```html
<form method="post" action="Shop.aspx?prod=4">
  Product: Nokia Infinity <br/>
  Price: 699 <br/>
  Quantity: <input type="text" name="quantity"> (Maximum quantity is 50)
  <br/>
  <input type="hidden" name="price" value="699">
  <input type="hidden" name="pricing_token" value="E76D213D291B8F216D694A34383150265C989229">
  <input type="submit" value="Buy">
</form>
```

The field `pricing_token` contains an opaque value, likely used by the server to verify or decrypt the pricing logic.

## Potential Inference

Even if you can’t immediately read the data, its presence suggests:

- The server likely performs some **decryption or integrity check** on the `pricing_token`.
- If the server uses the token to make security-critical decisions, it may be vulnerable to **replay attacks, substitution, or malformed payloads**.

## Common Use Cases

Opaque client-side data is frequently found in:

- Session tokens (e.g. in cookies)
- Anti-CSRF tokens (usually hidden form fields)
- One-time-use URLs or access tokens

These are typically discussed in detail in [Chapter 7](#).

## Hack Steps

When encountering opaque client-side data, you have multiple attack strategies:

### 1. Reverse Engineer the Obfuscation

If you **know the plaintext** (e.g., a product price), and you have its **corresponding opaque token**, you might deduce the **encoding/encryption logic**.

- Example: Try to map the plaintext-to-token pairs across different products.

### 2. Leverage Application Functionality

As explained in [Chapter 4](#), some parts of the application might **reflect opaque values** based on user-controlled input.

- If such a feature exists, use it to generate **custom tokens** for your desired payloads.

### 3. Perform Replay or Substitution Attacks

Even if you **can't decrypt** the token, you may:

- Copy the `pricing_token` from a **cheaper product**.
- Paste it into a **more expensive product's form**.
- If the server doesn’t validate product-to-token consistency, this may result in an unintended discount.

### 4. Submit Malformed Payloads

If the token must be parsed or decrypted on the server:

- Try submitting **overlong values**
- Use **different encodings** or **non-ASCII characters**
- Intentionally corrupt the structure

This could lead to:

- Application crashes
- Logic bypasses
- Vulnerabilities like buffer overflows or parsing errors

```http
pricing_token = %00%00%00%00%00%00%00%00%00%00
```