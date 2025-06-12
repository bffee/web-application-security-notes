# Identifying Entry Points for User Input

User input isn't limited to form fields. Inputs can exist in many parts of the HTTP request. Identifying all of them is vital for assessing attack vectors.

### Entry Points

* **URL file paths**: RESTful URLs can use path segments as input parameters:

```http
http://eis/shop/browse/electronics/iPhone3G/
```

* `electronics` and `iPhone3G` are treated as parameters

```http
http://eis/updates/2010/12/25/my-new-iphone/
```

* Year, month, day, and title are parameters

REST patterns are flexible and depend on developer implementation.

* **Request Parameters**:

  * Standard formats: `?param=value`
  * **Non-standard or custom formats**:

    ```
    /dir/file;foo=bar&foo2=bar2
    /dir/file?foo=bar$foo2=bar2
    /dir/file/foo%3dbar%26foo2%3dbar2
    /dir/foo.bar/file
    /dir/foo=bar/file
    /dir/file?param=foo:bar
    /dir/file?data=%3cfoo%3ebar%3c%2ffoo%3e%3cfoo2%3ebar2%3c%2ffoo2%3e
    ```
  * These may embed structured data like XML or custom delimiters. Be cautious when crafting payloads — ensure you inject within the actual processing logic.

### Caution

If you ignore custom formats and treat them as standard `param=value` pairs, you may miss vulnerabilities like:

* SQL injection
* Path traversal
* XML injection

Understanding the input format is key to targeting the right parts of the request.

---
## HTTP Headers

HTTP headers, though often overlooked, are a valuable source of user-controllable input and should always be considered when identifying potential attack surfaces in a web application. These headers are often used in server-side logic for logging, customization, analytics, and access control. Consequently, they can be vectors for various input-based attacks.


### Key HTTP Headers to Test

#### 1. **Referer Header**

* **Usage:** Indicates the address of the web page from which a request originated.
* **Attack Vector:** Applications might log this header or use it to tailor responses (e.g., highlighting search keywords).
* **Potential Issues:**

  * Persistent injection of HTML or script content.
  * Indirect influence on search engine indexing (SEO poisoning).
* **Example Attack:**

  * Set a malicious Referer URL with embedded JavaScript.
  * Send multiple requests to persist injected content in logs or pages.

#### 2. **User-Agent Header**

* **Usage:** Identifies the client software (e.g., browser or device).
* **Attack Vector:**

  * Reflected/persistent input injection.
  * Accessing alternative UI paths for different devices.
* **Why It Matters:**

  * Applications may serve different interfaces (mobile vs. desktop) with varying levels of security.
  * Less-tested mobile interfaces can expose unique vulnerabilities.
* **Tip:**

  * Use Burp Intruder with a built-in User-Agent payload list to detect interface changes.

#### 3. **X-Forwarded-For Header**

* **Usage:** Represents the original client IP address when a request goes through a proxy or load balancer.
* **Attack Vector:**

  * SQL injection or XSS if the application logs or parses this header insecurely.
  * Circumventing IP-based access controls.
* **Vulnerability Cause:** Developers often trust this header without validation, treating it as a reliable source of the client’s IP address.

---

### Additional Considerations

* **Custom Headers:** Some apps may rely on custom headers for debug functionality, API tokens, or feature toggles.
* **Header Injection:** If header values are echoed into responses, they could enable header injection attacks.

---

### HACK STEPS

1. **Inject Payloads** into the `Referer`, `User-Agent`, and `X-Forwarded-For` headers.
2. **Use Intruder** to iterate through payloads and detect anomalies (reflected content, different interfaces, etc.).
3. **Observe Behavior**:

   * Look for changes in page layout, content, or metadata.
   * Check server responses for injected payloads.
4. **Explore Alternative Interfaces** by spoofing mobile device headers.
5. **Test for Trust Assumptions** around client IPs by manipulating `X-Forwarded-For`.

---

### Summary

HTTP headers are often underutilized input vectors for security testing. By creatively manipulating headers such as `Referer`, `User-Agent`, and `X-Forwarded-For`, testers can uncover hidden functionality, bypass access controls, and identify input-based vulnerabilities like XSS and SQL injection. Always include header fuzzing as part of comprehensive application mapping and attack surface analysis.


---
## Out-of-Band Channels

Out-of-band channels refer to indirect or non-obvious avenues through which user-controllable input reaches the application. These are often not visible through standard HTTP requests and responses and typically require contextual understanding of the application’s broader architecture and use cases.

### Overview

* These entry points are outside the typical web request/response cycle.
* They may allow user-supplied data to enter the application through alternate routes.
* Often overlooked, they can be crucial for identifying subtle or hidden vulnerabilities.

### Characteristics

* **Not visible in normal HTTP traffic**: Cannot be identified simply by browsing the application and capturing traffic.
* **Context-aware discovery**: Often requires knowledge of how the application operates, integrates with other systems, or the environment in which it runs.

### Examples

1. **Webmail Applications**

   * Accept and render email received over SMTP.
   * Vulnerabilities like stored XSS can be introduced if malicious content is rendered within the web interface.

2. **Content Publishing Platforms**

   * Allow importing or retrieving content via HTTP from remote sources.
   * SSRF (Server-Side Request Forgery) and injection vulnerabilities can be present.

3. **Intrusion Detection Systems (IDS)**

   * Use sniffers to collect network data, which is displayed via a web UI.
   * Malicious data in captured packets might be improperly handled or displayed.

4. **Mobile or External APIs**

   * Applications that have public APIs used by mobile apps or external services.
   * If the backend logic merges data sources, user input through the API may affect web-facing components.

### Key Points

* **Broaden your perspective**: Don’t limit testing to visible HTTP interactions.
* **Consider all interfaces**: APIs, integrations, logs, imported content, and third-party services.
* **Use contextual clues**: Understand the business logic and backend processes to identify possible out-of-band data paths.

### Takeaway

To thoroughly map an application and its attack surface, testers must go beyond what is visible in HTTP traffic and actively seek out and analyze these hidden or indirect data entry points.

---
