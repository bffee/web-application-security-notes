# Circumventing Obstacles to Traversal Attacks

Even if initial traversal attempts fail, the application may still be vulnerable. Many developers implement input validation or filtering to block traversal payloads, but these filters are often flawed. Most bypass techniques exploit canonicalization issues and inconsistencies in how systems interpret file paths.

---

### HACK STEPS

* **Slash Variants**:
  * Use both `/` and `\` in traversal sequences.
  * Many filters check only one, while the underlying file system may support both.

* **Basic URL-Encoding of Traversal Sequences**:
  * Encode each character individually:
    * Dot — `%2e`
    * Forward slash — `%2f`
    * Backslash — `%5c`

* **16-bit Unicode Encoding**:
  * Use alternate Unicode formats:
    * Dot — `%u002e`
    * Forward slash — `%u2215`
    * Backslash — `%u2216`

* **Double URL-Encoding**:
  * Encode the `%` character itself:
    * Dot — `%252e`
    * Forward slash — `%252f`
    * Backslash — `%255c`

* **Overlong UTF-8 Encodings**:
  * Use malformed UTF-8 encodings to bypass strict filters:
    * Dot — `%c0%2e`, `%e0%40%ae`, `%c0ae`
    * Forward slash — `%c0%af`, `%e0%80%af`, `%c0%2f`
    * Backslash — `%c0%5c`, `%c0%80%5c`
  * These often work on systems with lenient or broken Unicode decoders, especially on Windows.

* **Recursive Sanitization Bypass**:
  * Some filters only sanitize input once. Nest traversal sequences to evade:
    * `....//`
    * `....\\/`
    * `..../\`
    * `....\\`

> You can automate these variants using Burp Intruder's illegal Unicode payload type to test all possible representations.

---

### Additional Filters and Bypasses

* **Suffix-Based File Type Filters**:
  * If the application validates file types using string functions (like `endsWith()`), try appending a null byte followed by an allowed extension:
    ```
    ../../../../../boot.ini%00.jpg
    ```
  * On many systems, the null byte (`%00`) truncates the string at the unmanaged level (e.g., C/C++ API), bypassing the check.

* **Appended Suffix Handling**:
  * If the application adds its own file-type suffix, the same `%00` null byte trick may still succeed.

* **Prefix-Based Directory Filters**:
  * If the application enforces that file paths begin with specific directories or filenames, try prepending the expected path:
    ```
    filestore/../../../../../../../etc/passwd
    ```

* **Combining Filters**:
  * Applications may implement both traversal sequence filters and file-type restrictions.
  * Combine bypass techniques to defeat both. For example:
    1. Try all traversal sequence variants until a path like `foo/../diagram1.jpg` works.
    2. If it still fails, test for file-type filtering:
       ```
       diagram1.jpg%00.jpg
       ```
    3. Try combining multiple bypasses in a single request.

* **Strategy**:
  * Work step-by-step from within the allowed directory.
  * Understand and isolate each filtering mechanism.
  * Use encoding, recursion, and combined payloads as needed.

* **Whitebox Testing**:
  * If source code access is available, determine the exact input processing logic.
  * Identify the real filename being passed to the filesystem, and construct payloads accordingly.

---