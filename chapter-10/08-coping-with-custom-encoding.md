# Coping with Custom Encoding

Some applications employ custom encoding schemes for obfuscating filenames, often as a weak defense mechanism. These schemes may seem to prevent direct path traversal but are typically flawed. A real-world case demonstrated how a custom encoding based on Base64 could be exploited without even decoding the algorithm.

---

### Vulnerability Context

* The application supported file upload and download within a workflow system.
* The **upload request** accepted a `filename` parameter vulnerable to path traversal when writing to disk.
* After upload, the application returned a **download URL** using an **obfuscated encoding** of the filename.

---

### Key Application Restrictions

* **No Overwriting**:
  * The application refused to write a file if one already existed.

* **Limited Write Permissions**:
  * The web server process had low privileges and could only write to non-critical locations.

* **Encoded Download URLs**:
  * Returned URLs encoded the filename using a **proprietary, position-based Base64-like scheme**.
  * Each position in the string used a different custom character set.
  * Arbitrary requests like `/etc/passwd` were not feasible without reverse-engineering this encoding.

---

### Exploitation Strategy

* Initial observation:
  * The obfuscated download URL included the **exact user-supplied string**.
  * For example:
    ```
    test.txt            → zM1YTU4NTY2Y
    foo/../test.txt     → E1NzUyMzE0ZjQ0NjMzND
    ```
  * This implied no **path canonicalization** occurred **before** encoding.

* This behavior allowed attackers to manipulate file paths to control the output of the obfuscated string.

---

### Exploit Execution

1. **Upload a file** using a crafted path:
   ```
   ../../../../../.././etc/passwd/../../tmp/foo
   ```
   * Canonically resolves to: `/tmp/foo`
   * The web server has permission to write here.

2. **Resulting download URL** contained a long encoded string:
   ```
   FhwUk1rNXFUVEJOZW1kNlRsUk5NazE2V1RKTmFrMHdUbXBWZWs1NldYaE5lb
   ```

3. **Truncate the string** precisely to match the desired canonical file path:
   ```
   FhwUk1rNXFUVEJOZW1kNlRsUk5NazE2V1RKTmFrM
   ```

4. **Result**:
   * Downloading with this truncated string returned the contents of `/etc/passwd`.
   * No decoding of the encoding scheme was necessary—only careful control of the input path and the resulting encoded boundary.

---

### NOTE

* The use of a **redundant `./`** in the filename was critical.
* Base64 encodes data in **3-byte blocks** into **4-character output**.
* Truncating the encoded string had to align with a **3-byte cleartext boundary** to avoid decoding errors.
* Without the `./`, the encoded string might have ended mid-block, causing the server to reject or misinterpret the request.

---

### Takeaway

Even custom encoding mechanisms can fail to provide security if:
* Input canonicalization is skipped before encoding.
* Attacker-controlled values are reused in output without strict validation.
* The encoding does not add cryptographic integrity or access controls.
