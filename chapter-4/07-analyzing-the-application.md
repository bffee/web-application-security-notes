# Analyzing the Application

Mapping isn't just about cataloging URLs. Understanding how an application works, including its logic and technology stack, is critical for identifying attack surfaces and preparing targeted tests.

### Key Investigation Areas

* **Core functionality**: Understand intended actions and business logic.
* **Peripheral behavior**: Look for off-site links, admin interfaces, logging, error messages.
* **Security mechanisms**: Investigate session management, access controls, and authentication (e.g., registration, password recovery).
* **User input points**: Examine every point where input is processed:

  * URLs (including REST paths)
  * Query strings
  * POST data
  * Cookies
  * HTTP headers (User-Agent, Referer, Accept, etc.)
* **Client-side technologies**: Forms, JavaScript, Java Applets, ActiveX, Flash, cookies.
* **Server-side stack**: Dynamic/static content, scripting languages, request parameters, SSL, web server types, back-end services (DB, mail).
* **Server structure**: Gain insight into backend mechanics via observed behavior.