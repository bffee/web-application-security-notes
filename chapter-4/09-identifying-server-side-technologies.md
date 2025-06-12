# Identifying Server-Side Technologies

Understanding the server-side technologies behind a web application is vital for mapping its architecture, attack surface, and potential vulnerabilities. This process often requires gathering evidence from a variety of sources, such as server responses, URL structures, session cookies, and more.

---

### Banner Grabbing

---

The most straightforward approach to identifying technologies is **banner grabbing**, which involves inspecting HTTP headers returned by the server—especially the `Server` header. For example:

```
Server: Apache/1.3.31 (Unix) mod_gzip/1.3.26.1a PHP/4.3.9 mod_ssl/2.8.20 OpenSSL/0.9.7a
```

This reveals the web server software (Apache), platform (Unix), installed modules (mod\_ssl), scripting language (PHP), and cryptographic library (OpenSSL). Similar information might also appear in:

* **HTML page templates** (e.g., comments or metadata)
* **Custom HTTP headers** like `X-Powered-By`
* **URL query strings** that include versioning or technology hints

*Note:* Administrators can often suppress or falsify these headers, so you should treat them as indicators, not proof.

---

### HTTP Fingerprinting

---

If banners are missing, generic, or misleading, attackers can use **HTTP fingerprinting** to deduce the server’s identity based on subtle differences in its behavior. Examples include:

* How the server handles malformed requests
* Support for unusual HTTP methods
* Specific headers in redirects or error responses
* How it responds to crafted edge-case input

**Httprecon** and **httprint** are tools designed to automate this behavioral analysis and compare results to known server profiles, producing a ranked list of likely technologies in use.

---

### File Extensions and Their Behavior

---

The extensions used in URL paths often indicate which back-end technology is being used. Some common ones include:

* `.asp` — Classic ASP (Microsoft)
* `.aspx` — ASP.NET
* `.jsp` — Java Server Pages
* `.cfm` — ColdFusion
* `.php` — PHP
* `.pl` — Perl
* `.py` — Python
* `.dll` — Native compiled libraries
* `.nsf`, `.ntf` — Lotus Domino
* `.d2w` — IBM WebSphere

Even if an application does not visibly use these extensions, you can probe them by making requests to nonexistent files (e.g., `/fakepage.aspx`). The resulting error messages are often framework-specific:

* A detailed ASP.NET error page indicates the ASP.NET runtime is active.
* A generic 404 might suggest the extension isn’t mapped at all.

Because web servers associate file extensions with specific handlers (like DLLs in IIS), inconsistent behavior across extensions can expose which technologies are mapped—and potentially exploitable.

---

### Directory Naming Conventions

---

Certain directory names serve as telltale signs of specific platforms or technologies. Some common examples:

* `/servlet/` — Java Servlets
* `/pls/` — Oracle PL/SQL Gateway
* `/cfdocs/`, `/cfide/` — ColdFusion admin and documentation paths
* `/SilverStream/` — SilverStream application paths
* `/WebObjects/`, `.woa` — Apple WebObjects
* `/rails/` — Ruby on Rails

These directories are often part of default installations or legacy components that weren’t removed.

---

### Session Token Patterns

---

The naming pattern of session cookies can also indicate the application platform:

* `JSESSIONID` — Java-based servers (e.g., Tomcat, JBoss)
* `ASPSESSIONID` — Classic ASP on IIS
* `ASP.NET_SessionId` — ASP.NET framework
* `PHPSESSID` — PHP applications
* `CFID`, `CFTOKEN` — ColdFusion

During testing, observing which session identifier is set can help infer the server environment.

---

### Identifying Third-Party Components

---

Applications often integrate third-party components for common tasks like shopping carts, authentication, or forums. These can be:

* **Commercial components** (e.g., a license-based payment module)
* **Open-source plugins** (e.g., for CMS platforms like WordPress)

Identifying these components is important because:

* They may have **known vulnerabilities** (search CVEs or exploit databases)
* Their **functionality and parameters** may be predictable if used in other sites
* You can **download and analyze** open-source components locally to discover internal logic and security flaws

Clues for identifying third-party components include:

* Script paths like `/cart.js`, `/user/login/`
* Cookie names like `wp-settings`, `woocommerce_cart_hash`
* Comments or error messages disclosing software names

Even if the branding is customized, the internal structure (e.g., form names, input parameters) often remains consistent across implementations.

---

### HACK STEPS

---

1. **Map all user input entry points:** Look at URLs, GET/POST parameters, cookies, and headers.

2. **Decode non-standard query structures:** If the app uses custom parameter formats, try to reverse-engineer the name/value encoding.

3. **Investigate out-of-band input channels:** Look for integrations that import data via SMTP, external HTTP requests, or sniffers.

4. **Inspect the `Server` header:** Note variations across different pages or components—some might be served by separate back-ends.

5. **Look for tech hints in HTML or headers:** Check HTML comments, meta tags, or custom headers that might disclose platforms or libraries.

6. **Use HTTP fingerprinting tools:** Run tools like `httprint` or `httprecon` to correlate server behavior with known technologies.

7. **Scan for technology-specific file extensions:** Probe with `.php`, `.aspx`, `.jsp`, etc., and observe differences in error handling.

8. **Cross-reference disclosed software versions:** Search for publicly known vulnerabilities using CVE databases (see Chapter 18).

9. **Analyze URL paths and directory names:** Look for telltale tech-specific subdirectories like `/cfide/` or `/servlet/`.

10. **Observe session token names:** Match cookie names to known platforms (e.g., `PHPSESSID`, `JSESSIONID`).

11. **Google custom cookie/script/header names:** Find documentation or examples of similar usage in other apps.

12. **Analyze third-party components:**

    * Compare with similar implementations
    * Download open-source components
    * Review documentation or changelogs
    * Identify hidden features or legacy functionality

---

By combining passive techniques (like analyzing banners and cookies) with active probing (such as requesting invalid URLs), you can build a rich understanding of the server-side environment. This knowledge lays the groundwork for deeper testing, enumeration, and targeted exploitation.
