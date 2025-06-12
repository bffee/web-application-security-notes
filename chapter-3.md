# Chapter 3: Web Application Technologies

## 1. The HTTP Protocol

### 1.1 HTTP Requests

HTTP is a request-response protocol. Each **HTTP request** has the following structure:

* **Request Line**: Contains the HTTP method (e.g., `GET`), the resource path (e.g., `/index.html`), and the version (e.g., `HTTP/1.1`).
* **Headers**: Provide metadata (like content type, cookies, caching instructions).
* **Body** (optional): Data sent with the request, typically present in `POST`, `PUT`, and similar methods.

Example:

```
POST /submit HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 27

username=admin&password=pass
```

### 1.2 HTTP Responses

A **response** from the server includes:

* **Status Line**: E.g., `HTTP/1.1 200 OK`
* **Headers**: Such as `Content-Type`, `Set-Cookie`, etc.
* **Body**: Contains the actual content like HTML, JSON, etc.

---

### 1.3 HTTP Methods

* `GET`: Retrieves a resource. Parameters go in the URL. Should not change server state.
* `POST`: Sends data to the server. Parameters go in the body. Common for forms.
* `HEAD`: Same as `GET` but no body returned. Used to test links or content existence.
* `PUT`: Replaces a resource with provided content.
* `DELETE`: Deletes a resource.
* `OPTIONS`: Lists supported methods. Useful in discovering functionality.
* `TRACE`: Echoes the received request. Can expose reflected data in XST attacks.

Some methods like `CONNECT`, `PROPFIND`, or WebDAV extensions (e.g., `MKCOL`) can also be enabled and abused.

---

### 1.4 HTTP Headers

#### General Headers

* `Connection`: Whether the TCP connection should remain open (Keep-Alive) or be closed.
* `Content-Encoding`: e.g., `gzip` indicates compressed content.
* `Content-Length`: Number of bytes in the body.
* `Content-Type`: MIME type of the content (e.g., `text/html`, `application/json`).
* `Transfer-Encoding`: Chunked responses.

#### Request Headers

* `Accept`: Types of responses the client can handle.
* `Accept-Encoding`: Compression schemes acceptable to client.
* `Authorization`: Credentials for Basic or Digest auth.
* `Cookie`: Sends stored cookies to server.
* `Host`: Indicates target hostname, especially important for virtual hosts.
* `If-Modified-Since` / `If-None-Match`: For caching; if content hasn't changed, server returns 304.
* `Referer`: Originating page URL. Can leak sensitive data.
* `User-Agent`: Info about client software.

#### Response Headers

* `Access-Control-Allow-Origin`: CORS control.
* `Cache-Control`: Prevent or allow caching.
* `ETag`: Versioning identifier for cache validation.
* `Expires`: Expiration time of cached content.
* `Location`: Redirect target.
* `Pragma`: Cache control directive.
* `Server`: Web server name/version.
* `Set-Cookie`: Issues cookies.
* `WWW-Authenticate`: Used with 401 status to prompt authentication.
* `X-Frame-Options`: Clickjacking defense.

---

### 1.5 URLs

A URL (Uniform Resource Locator) includes:

```
http://hostname[:port]/path?query
```

* **Scheme**: Protocol, e.g., `http`, `https`
* **Hostname**: Domain or IP
* **Port**: Optional (default: 80 for HTTP, 443 for HTTPS)
* **Path**: File or resource on the server
* **Query**: Key-value pairs sent as part of the request

Relative URLs (e.g., `/page.html`) and absolute URLs (e.g., `https://example.com/page.html`) behave differently in navigation and are relevant in redirect and SSRF testing.

---

### 1.6 REST

**Representational State Transfer (REST)** is a stateless architecture style. REST-style URLs typically put parameters in the path:

* Query string style: `/search?car=ford&model=pinto`
* REST style: `/search/ford/pinto`

REST emphasizes statelessness, resource-based addressing, and uses standard HTTP verbs.

---

### 1.7 Cookies

Cookies are key-value pairs stored in the browser and submitted automatically with requests. Set by `Set-Cookie` response header.

#### Structure:

```
Set-Cookie: sessionId=abc123; HttpOnly; Secure; Path=/; Domain=example.com; Expires=Tue, 15 Jun 2025 12:00:00 GMT
```

#### Attributes:

* `Expires`: Expiry time (persistent cookies)
* `Domain`: Scope of domains where cookie is valid
* `Path`: URL path restriction
* `Secure`: Sent only over HTTPS
* `HttpOnly`: Not accessible via JavaScript (mitigates XSS)

Poor cookie security can lead to session fixation or hijacking.

---

### 1.8 Status Codes

Grouped by first digit:

* `1xx`: Informational — `100 Continue`
* `2xx`: Success — `200 OK`, `201 Created`
* `3xx`: Redirection — `301 Moved Permanently`, `302 Found`, `304 Not Modified`
* `4xx`: Client errors — `400 Bad Request`, `401 Unauthorized`, `403 Forbidden`, `404 Not Found`
* `5xx`: Server errors — `500 Internal Server Error`

Useful for probing misconfigurations and identifying application behavior.

---

### 1.9 HTTPS

Encrypts HTTP using TLS/SSL:

* Prevents sniffing, tampering, and MITM
* Requires server-side certificate
* Inspect for weak ciphers, outdated protocols, expired certs

---

### 1.10 HTTP Proxies

Proxies can log, alter, or filter requests. Types:

* **Forward**: Client-side proxy like Burp/ZAP
* **Reverse**: Server-side proxy
* **Transparent**: Operates without client config

Used for intercepting/modifying HTTP traffic.

---

### 1.11 HTTP Authentication

Mechanisms to protect resources:

* **Basic**: Base64-encoded `username:password` in header. Insecure without HTTPS.
* **Digest**: Includes nonce and hashed credentials.
* **NTLM/Kerberos**: Used in enterprise environments.

Header example:

```
Authorization: Basic dXNlcjpwYXNz
```

---

## 2. Web Functionality

### 2.1 Server-Side Functionality

Server-side functionality refers to the code and processes that execute on the web server to generate dynamic content, interact with back-end systems, and respond to client requests. Web applications today rely heavily on server-side logic to deliver personalized, stateful experiences.

#### Server-Side Inputs

A server can accept input via:

* **Query strings**: `/search?q=admin`
* **RESTful path segments**: `/user/admin`
* **HTTP cookies**: Sent automatically by the browser
* **POST body**: Typically used in form submissions
* **Request headers**: Such as `User-Agent`, `Referer`, etc.

#### Languages and Frameworks

##### 1. **Java Platform (J2EE / Java EE)**

Java EE (Enterprise Edition) is a robust platform for enterprise-grade applications.

* **Java Servlets**: Java classes extending HTTP-specific behavior; handle requests and generate responses.
* **Enterprise JavaBeans (EJBs)**: Modular, reusable server-side components handling business logic. Designed for scalability, security, and transactions.
* **POJOs (Plain Old Java Objects)**: Simple Java objects, lightweight alternatives to EJBs.
* **JSP (JavaServer Pages)**: Combine HTML and Java code. Compiled into servlets.
* **Web Containers**: Runtime environments like Apache Tomcat, JBoss, and WebLogic for executing servlets and JSPs.
* **Common Frameworks**:

  * **Spring**: Dependency injection, REST support
  * **Hibernate**: ORM (Object-Relational Mapping)
  * **Struts**: MVC architecture
  * **SiteMesh/Tapestry**: Presentation and templating
  * **JAAS, ACEGI**: Authentication and security
  * **Log4J**: Logging framework

##### 2. **ASP.NET (.NET Framework)**

ASP.NET is Microsoft’s framework for web applications, built on the .NET platform.

* **Languages**: C#, VB.NET, F#
* **CLR (Common Language Runtime)**: Executes .NET code in a sandbox.
* **Web Forms**: Event-driven model mimicking desktop applications.
* **MVC Pattern**: ASP.NET MVC separates business logic (Model), UI (View), and input control (Controller).
* **Web.config**: XML-based config file defining session behavior, error handling, and more.
* **Security Features**:

  * Built-in XSS filtering
  * Request validation
  * HttpOnly and Secure cookies

**Drawback**: Simple for beginners, leading to insecure code due to lack of developer awareness.

##### 3. **PHP**

PHP is a dynamic scripting language embedded in HTML. It is commonly used with the LAMP stack:

* **L**inux (OS)

* **A**pache (Web server)

* **M**ySQL (Database)

* **P**HP (Scripting language)

* **Features**:

  * Loose typing, quick development
  * Huge ecosystem of libraries and CMS (WordPress, Drupal)
  * Easy database integration via MySQLi, PDO

* **Popular PHP-based tools**:

  * Forums: PHPBB, PHP-Nuke
  * Admin: PHPMyAdmin
  * Webmail: SquirrelMail
  * Shopping Carts: osCommerce
  * Wikis: MediaWiki

**Security Note**: Historically poor defaults and wide use among beginners led to many vulnerable apps.

##### 4. **Python**

Python has gained popularity with frameworks like:

* **Django**: Batteries-included, secure by default (CSRF, XSS protection)
* **Flask**: Lightweight micro-framework, suitable for APIs

**Key Features**:

* Built-in ORM
* Jinja2 templating
* Middleware extensibility

Python is often used for both front-end APIs and back-end services.

##### 5. **JavaScript on the Server (Node.js)**

* **Node.js**: Executes JavaScript outside the browser using the V8 engine
* **Express.js**: Popular Node.js framework for REST APIs and web apps

**Features**:

* Event-driven, non-blocking I/O
* Lightweight and fast
* Easily integrates with frontend code

**Security Risks**:

* Prototype pollution
* Dependency vulnerabilities (via NPM packages)

#### Other Server Components

* **Web Servers**: Apache, Nginx, Microsoft IIS, and Netscape Enterprise Server
* **Databases**: SQL-based (MySQL, MSSQL, Oracle) and NoSQL (MongoDB, Redis)
* **Directory Services**: LDAP, Active Directory
* **Web Services**: SOAP and REST APIs, often consumed via client apps
* **Filesystems**: Accessed for uploads/downloads; vulnerable to path traversal

#### Myth: Secure Because of Framework

It is a myth that simply using a popular framework ensures security:

* Many vulnerabilities stem from poor design, not implementation
* Third-party plugins are rarely reviewed
* Developers often misunderstand framework limitations

**Example**: A widely used Java package may have an XSS flaw in templating or logging. An attacker who knows the framework can exploit this without needing to reverse-engineer application-specific logic.

---

### 2.2 Client-Side Functionality

Executed in browser:

* **HTML**: Structure
* **CSS**: Styling
* **JavaScript**: Logic and behavior
* **AJAX**: Background HTTP requests
* **DOM**: Dynamic document model

Client-side logic is easily bypassed. Always test server validation.

### 2.3 HTML and XHTML

* HTML: Loosely structured
* XHTML: Stricter, XML-compliant

### 2.4 Hyperlinks

Anchor elements with `href` attribute used for navigation.
Can embed GET parameters.

### 2.5 Forms

Forms send user input:

* `method="GET|POST"`
* Input types: `text`, `password`, `submit`, `hidden`
* Form validation may occur client-side (e.g., JavaScript)

### 2.6 State and Sessions

HTTP is stateless. Applications use sessions:

* ID stored in cookies, hidden fields, or URL
* Must be unpredictable
* Attacks: fixation, hijacking, prediction

---

## 3. Encoding Schemes

### 3.1 URL Encoding

* `%20` for space, `%26` for `&`
* Used in query strings
* Essential in crafting payloads

### 3.2 Unicode Encoding

* `%uXXXX` format
* May bypass filters

### 3.3 HTML Encoding

* Converts special characters to entities:

  * `<` → `&lt;`, `>` → `&gt;`, `&` → `&amp;`
* Prevents rendering of injected HTML/JS

### 3.4 Base64 Encoding

* Converts binary to printable ASCII
* Used in Basic Auth, binary payloads
* Not encryption

Example:

```
admin:pass → YWRtaW46cGFzcw==
```

### 3.5 Hex Encoding

* ASCII values represented as hex (e.g., `\x41` = `A`)
* Used in cookies, URLs

### 3.6 Remoting and Serialization Frameworks

Allow client-side code to call server functions and pass structured data:

* Automatically serialize/deserialize objects
* Examples:

  * **Flex + AMF**
  * **Silverlight + WCF**
  * **Java serialized objects**
* Vulnerabilities:

  * Insecure deserialization (RCE)
  * Parameter tampering
  * Logic abuse

---

## 4. Common Data and Markup Technologies

### 4.1 SQL

* Structured Query Language
* Interface to relational databases
* Used for all CRUD operations
* Target of SQL injection

### 4.2 XML

* Markup language using tags/attributes
* Supports nesting, schemas, DTDs
* Used in SOAP, configuration files

### 4.3 Web Services

* Use XML over HTTP (SOAP)
* WSDL defines service endpoints
* Tools like soapUI can test them
* Vulnerabilities:

  * Input injection
  * Misconfigured access controls

---

## 5. Modern Client-Side Enhancements

### 5.1 JSON

* Lightweight data format
* Easier than XML for AJAX

### 5.2 AJAX

* Asynchronous HTTP requests using JavaScript
* Enables dynamic page updates

### 5.3 Same-Origin Policy

* JS can only access data from same origin
* Controls cookie, DOM, and AJAX access

### 5.4 HTML5

* New tags, APIs, and storage mechanisms
* New attack surfaces: XSS, client-side SQLi

### 5.5 Web 2.0

* Emphasis on AJAX, interactivity, user-generated content
* Doesn’t change threat landscape but adds complexity

### 5.6 Browser Extension Technologies

* Native plug-ins/add-ons:

  * Java applets
  * ActiveX controls
  * Flash/Silverlight
* May include native code execution

---
