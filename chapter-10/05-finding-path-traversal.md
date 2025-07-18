# Finding and Exploiting Path Traversal Vulnerabilities

When a web application uses user input to read or write files on the server, it may introduce path traversal vulnerabilities. These flaws can allow attackers to access sensitive files (e.g., config files, logs) or even overwrite critical components, potentially leading to full system compromise. While some apps include defenses, they are often poorly implemented and can be bypassed with crafted input or encoding tricks.

---

### Locating Targets for Attack

* **Identify common file-based features**: Look for endpoints where users upload, retrieve, or preview files, such as:
  * Document sharing systems.
  * Blog or auction platforms that allow image uploads.
  * Applications offering downloadable PDFs, reports, or manuals.

* **Look for indirect file system access**: Even if file features aren’t obvious, some parameters may still reference server files (e.g., templates, includes).

* **Watch for suspicious parameter names**: Parameters like `filename=`, `include=`, `template=`, or `path=` can indicate backend file usage.

* **Observe app behavior during other tests**: Input-based errors, stack traces, or unusual outputs may hint at file access operations.

---

### HACK STEPS

* **During Initial Testing**:
  * Look for any parameter that appears to handle file or directory names (e.g., `include=main.inc`, `template=/en/sidebar`).
  * Identify functionality that likely interacts with the file system (e.g., document preview, image display).
  * Monitor for anomalies such as internal errors or server path disclosures during unrelated testing.

* **If You Have Local Access to the App**:
  * Use system-level tools to trace file activity:
    * **Windows**: `FileMon` from SysInternals.
    * **Linux**: `strace`, `ltrace`.
    * **Solaris**: `truss`.

  * Insert a unique marker (e.g., `traversaltest`) into every parameter (query, body, cookies, headers), testing one at a time.
  
  * Apply filters in your file monitoring tool to detect events where your test string appears in file names.

  * Investigate every match:
    * If the input is used in a file operation, test it for path traversal using sequences like `../` or encoded variations.

---
