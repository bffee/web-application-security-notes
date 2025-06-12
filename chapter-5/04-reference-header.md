# The Referer Header

## Overview

The `Referer` (sic) HTTP header is commonly used by browsers to indicate the source URL from which a request was initiated. This may happen through user actions like clicking a link or submitting a form, or through page-embedded resources like images. Some developers mistakenly rely on the `Referer` header as a mechanism for validating client-side behavior or controlling application flow.

## Misuse Example

### Intended Use

Consider a password reset mechanism that expects users to navigate through a defined series of steps. The server uses the `Referer` header to validate that the request to reset the password comes from the proper step:

```http
GET /auth/472/CreateUser.ashx HTTP/1.1
Host: mdsec.net
Referer: https://mdsec.net/auth/472/Admin.ashx
```

The server checks whether the `Referer` header matches the expected source (e.g., `Admin.ashx`) before processing the password reset.

### Attack Vector

Because the entire HTTP request—including headers—is under user control, an attacker can bypass this protection easily by:

1. Navigating directly to `CreateUser.ashx`.
2. Using an intercepting proxy to spoof the `Referer` header with the expected value.

This renders the check ineffective and allows users to access sensitive functionality without following the intended sequence.

## Standards and Reality

- The `Referer` header is **optional** per [W3C standards](https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html).
- Not all clients send it.
- Trusting it for security purposes is inherently flawed.

## Common Myth

Some developers mistakenly believe that HTTP headers (like `Referer` and `Cookie`) are more secure or less tamperable than other request components like URLs or form parameters. This is incorrect.

> Given the widespread availability of intercepting proxies, **any** part of a request—headers, body, parameters—can be modified with ease.

Relying on headers for access control or validation introduces serious vulnerabilities.

## Hack Steps

1. **Identify all client-transmitted data**: Search for use of hidden form fields, cookies, URL parameters, or headers like `Referer` in the application logic.
2. **Determine function**: Try to infer what the data is being used for, based on parameter names, context, or behavior.
3. **Modify values**: Manipulate them using a proxy and observe whether the application processes arbitrary values. If it does, check whether this leads to unauthorized actions or information disclosure.

