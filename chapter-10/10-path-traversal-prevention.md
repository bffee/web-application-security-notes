# Preventing Path Traversal Vulnerabilities

The most effective way to prevent path traversal attacks is to **avoid using user-supplied input with filesystem APIs**. In many cases, this functionality is unnecessary and can be redesigned to eliminate the attack surface entirely.

---

## Safer Design Alternatives

When file access does not require dynamic logic, simpler and safer alternatives exist:

* **Use direct URLs to static files**:
  * If files like `keira.jpg` do not require access control, they can be placed inside the web root and accessed directly.
  
* **Implement file identifiers instead of filenames**:
  * Use numeric or mapped identifiers (e.g., `id=5`) referencing a hard-coded list of allowed files.
  * Requests with invalid identifiers can be cleanly rejected, preventing filename manipulation.

---

## When User-Supplied Filenames Are Necessary

In workflows where users must upload and download files using filenames, developers may choose to handle user input. In these cases, a **defense-in-depth** strategy is critical, combining multiple safeguards to reduce risk.

---

## Recommended Defensive Measures

* **Validate After Canonicalization**:
  * Fully decode and canonicalize the input path first.
  * Then reject requests containing:
    - Path traversal sequences (`../`, `..\`)
    - Null bytes (`%00`)
  * **Avoid sanitizing** the path; reject it entirely.

* **Restrict File Types**:
  * Enforce a hard-coded allowlist of acceptable file extensions.
  * Apply this check *after* decoding and canonicalization.

* **Verify Canonical Path Against Base Directory**:
  * Use secure filesystem methods to confirm that the target file stays within a designated start directory:
    - **Java**:
      ```java
      File file = new File(userInput);
      String canonical = file.getCanonicalPath();
      if (!canonical.startsWith(startDirectory)) reject();
      ```
    - **ASP.NET**:
      ```csharp
      string fullPath = Path.GetFullPath(userInput);
      if (!fullPath.StartsWith(startDirectory)) reject();
      ```

* **Use a Chrooted Environment**:
  * On UNIX systems, isolate file access to a chroot jail. This makes the chrooted directory behave like the root (`/`), rendering `../` ineffective.
  * On Windows, mount the start directory as a new logical drive (e.g., `X:\`) to restrict access outside of it.

* **Integrate with Logging and Alerting Systems**:
  * Treat any path traversal attempt as a **security event**:
    - Log full request details.
    - Terminate the user’s session.
    - Optionally suspend the account.
    - Generate an administrative alert.

---

## Summary

* Prefer static file paths or mapped identifiers to remove input from the equation.
* When dynamic filenames are required, combine strict validation, canonical checks, filesystem isolation, and monitoring.
* Never trust the input path—even after sanitization.
