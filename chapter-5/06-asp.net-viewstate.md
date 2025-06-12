# The ASP.NET ViewState


The **ASP.NET ViewState** is a hidden form field used by default in ASP.NET applications. It allows the server to persist the state of a web page between requests **without storing the state on the server side**. Instead, state information is **serialized and sent to the client**, then sent back with subsequent requests.

This mechanism improves server performance but introduces security risks if not properly protected.

## How ViewState Works

The ViewState is included as a hidden input:

```html
<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE"
value="/wEPDwULLTE1ODcxNjkwNjIPFgIeBXByaWNlBQMzOTlkZA==" />
```

It stores data like:

```csharp
string price = getPrice(prodno);
ViewState.Add("price", price);
```

When the user submits the form:

```http
POST /shop/76/Shop.aspx?prod=3 HTTP/1.1
Host: mdsec.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 77

__VIEWSTATE=%2FwEPDwULLTE1ODcxNjkwNjIPFgIeBXByaWNlBQMzOTlkZA%3D%3D&quantity=1
```

The ViewState field carries the data (like `price=399`) in **Base64-encoded** format. The server deserializes it to reconstruct the state.

## ViewState Characteristics

- **Base64-Encoded**: Can be decoded using a Base64 decoder.
- **Binary Serialized Format**: Once decoded, the structure reveals the data.
- **MAC Protection**: By default, ASP.NET adds a **Message Authentication Code (MAC)** to the ViewState to prevent tampering. This can be disabled, intentionally or by misconfiguration.

### Important Note

If decoding a Base64 string yields garbage, try decoding from different starting positions (because Base64 is block-based: every 4 encoded bytes → 3 decoded bytes).

## Security Implications

- If **MAC protection is disabled**, the ViewState can be **tampered with** to inject or change data (e.g., change product prices).
- Even if MAC-protected, the ViewState may expose **sensitive internal data** useful for reconnaissance.

## Burp Suite Integration

- **ViewState Parser**: Burp detects and parses ViewState fields.
- If **MAC is disabled**, Burp allows editing the ViewState using its **hex editor**.
- You can **manipulate values** like price or product ID in the ViewState and forward it to the server.


## Hack Steps

1. **Check for MAC Protection**:
   - Look for a 20-byte hash at the end of the ViewState.
   - Use Burp’s ViewState parser to confirm.

2. **Analyze the ViewState**:
   - Decode the ViewState and inspect the content.
   - Look for sensitive or custom data like prices, user roles, IDs, etc.

3. **Test Modification**:
   - Try modifying one parameter in the ViewState (e.g., `price`).
   - Submit and observe whether errors occur.

4. **Exploit if Editable**:
   - If modification is possible without error, identify sensitive parameters.
   - Attempt to inject malicious or manipulated values.
   - Treat parameters like any other client-side data (e.g., fuzzing, tampering, injection).

5. **Test Per-Page**:
   - MAC protection may vary between pages.
   - Test all significant application pages for ViewState vulnerabilities.

6. **Use Passive Scanning**:
   - Burp Scanner (passive mode) automatically reports ViewState fields **without MAC protection**.
