# Detecting Path Traversal Vulnerabilities

Once you identify potential targets for path traversal testing, you must test each parameter individually to determine if user input is passed unsafely to file system operations. A reliable first step is to use traversal sequences that don’t go above the application's starting directory to check whether such input is blocked, normalized, or accepted as-is.

---

### HACK STEPS

* **Initial Test Without Traversing Above the Root**:
  * Assume the parameter is appended to a preset directory (e.g., `file=foo/file1.txt`).
  * Submit a variation using traversal inside a subdirectory:
    ```
    file=foo/bar/../file1.txt
    ```
  * If behavior remains unchanged, the application likely performs path normalization and may be vulnerable.

* **If the Application Behavior Changes**:
  * It may be filtering or sanitizing traversal sequences.
  * You should proceed to test known bypass techniques (covered in the next section).

> Most file systems canonicalize paths, so `bar/../file1.txt` resolves to `file1.txt`, even if `bar` doesn’t exist.

* **Test for Traversing Above the Root**:
  * If the function offers **read access**, try accessing known world-readable OS files:
    * UNIX:
      ```
      ../../../../../../../../../../../../etc/passwd
      ```
    * Windows:
      ```
      ../../../../../../../../../../../../windows/win.ini
      ```
  * If successful, contents of the file will be displayed, confirming the vulnerability.

* **Test for Write Access Vulnerability**:
  * Submit two filenames — one likely writable and one that shouldn't be:
    * Windows:
      ```
      ../../../../../../../../../../../../writetest.txt
      ../../../../../../../../../../../../windows/system32/config/sam
      ```
    * UNIX:
      ```
      ../../../../../../../../../../../../tmp/writetest.txt
      ../../../../../../../../../../../../tmp
      ```
  * If the application behaves differently for the two paths (e.g., success vs. error), it’s likely vulnerable.

* **Alternative Verification via File Upload**:
  * Attempt to write a file into the web root and retrieve it via browser.
  * Success confirms write access, but this may fail if:
    * You don’t know the web root path.
    * The app’s file operations lack write permissions there.

---

### TIP

* Always use **excessive traversal sequences** like `../../../../...` to cover deep base directories and avoid false negatives.
* Most file systems **ignore redundant traversal beyond root**, so overstepping won’t usually cause errors.
* **Slash handling**:
  * Windows: accepts both `\` and `/`.
  * UNIX: accepts only `/`.
  * Some apps may filter only one type — try both to ensure coverage.
* Even if the frontend is UNIX-based, the backend component may be on Windows. Always test with both separators.
