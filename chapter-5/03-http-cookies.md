# HTTP Cookies

## Overview

HTTP cookies are another common mechanism used by web applications to transmit data via the client in a way that appears unmodifiable to the end user. Just like hidden form fields, cookies are not visible on-screen, and users cannot directly change them through the browser interface. However, they are entirely under the user’s control and can be intercepted and modified using tools like an intercepting proxy.

## Security Assumptions and Flaws

Developers often rely on the fact that cookies are not normally altered by users and use them to store sensitive data or make business logic decisions. This assumption is fundamentally flawed because:

- Users have full control over client-side data.
- Intercepting proxies can be used to view and modify both server-set cookies and client-sent cookies.

## Example Scenario

### Original Server Response

After a customer logs into the application, they receive an HTTP response with a cookie that appears as follows:

```http
HTTP/1.1 200 OK
Set-Cookie: DiscountAgreed=25
Content-Length: 1530
```

Here, the application assumes the client will retain this `DiscountAgreed=25` value and return it unchanged. However, the user can intercept and manipulate this value before it is sent back to the server.

### Manipulated Client Request

Using an intercepting proxy, the user modifies the cookie in a subsequent request:

```http
POST /shop/92/Shop.aspx?prod=3 HTTP/1.1
Host: mdsec.net
Cookie: DiscountAgreed=90
Content-Length: 10

quantity=1
```

### Vulnerability

If the server accepts and trusts the manipulated cookie, the user can illegitimately increase their discount and gain unauthorized benefits.

## Key Takeaways

- **Never trust cookies for critical decisions** unless they are securely signed or encrypted and validated on the server.
- **Use secure server-side validation** to ensure that values coming from cookies are not arbitrarily accepted.
- **Interception tools like Burp Suite** make it trivial for attackers to manipulate cookie values, making client-side reliance on cookies for access control or pricing decisions highly insecure.

