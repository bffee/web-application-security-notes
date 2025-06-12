# 🔍 Discovering Hidden Content

## 📌 Overview
Web applications often contain **non-linked, hidden content**, such as:
- Functionality for testing or debugging purposes.
- Features available only to specific user roles (e.g., admins).
- Backup files, old versions, or archived directories.
- Misconfigured or default resources in off-the-shelf applications.
- Source files, logs, and developer comments.

These are usually **not discoverable** via standard spidering.

---

## 🕳️ Common Examples of Hidden Content
- **Backup Files**: e.g., `index.bak`, `login.old`, often containing sensitive logic.
- **Archives**: `.zip`, `.tar`, `.rar` containing source or config files.
- **Test Functionality**: Unlinked pages deployed for internal testing.
- **Default Features**: From prebuilt platforms but unlinked in the UI.
- **Old Versions**: e.g., `register_old.php`, possibly vulnerable.
- **Config/Include Files**: Might contain credentials or server paths.
- **Source Code**: Accidentally exposed `.java`, `.cs`, `.py`, etc.
- **HTML Comments**: May leak endpoints, usernames, or passwords.
- **Log Files**: e.g., `access.log`, `debug.log` with session or input data.

---

## 🔄 Brute-Force Techniques

### 🛠️ Purpose
Automate requests to **guess resource names** and find unlinked content.

### 🧱 Base URLs (from spidering):
- `/auth/Login`
- `/auth/ForgotPassword`
- `/home/`
- `/pub/media/100/view`
- `/images/eis.gif`
- `/include/eis.css`

### 🗂️ Example Brute-Force Directory Requests:
- `/About/`
- `/abstract/`
- `/academics/`
- `/accessibility/`
- `/accounts/`
- `/action/`

Use **Burp Intruder** to automate requests and capture responses.
Sort results by **status code** or **response length** to identify valid paths.

### 📄 File Brute-Force in `/auth/`:
- `/auth/About/`
- `/auth/AddUser/`
- `/auth/Admin/`
- `/auth/Administration/`
- `/auth/Admins/`

Discovered Resources:
- `/auth/Login`
- `/auth/Logout`
- `/auth/Register` → Missed by spider, may allow self-registration
- `/auth/Profile` → `302` redirect to login, implies auth-only access

---

## 📊 HTTP Status Code Interpretation

| Code | Interpretation |
|------|----------------|
| `200 OK` | Resource exists and is accessible |
| `302 Found` | Likely restricted; check redirect target |
| `400 Bad Request` | Possibly malformed URL or invalid encoding |
| `401 Unauthorized` / `403 Forbidden` | Resource exists but is blocked |
| `500 Internal Server Error` | Resource may require parameters; app error |

⚠️ Many apps do **not return `404`** for invalid resources — they may return custom error pages with `200 OK`.

---

## 🧪 Hack Steps

1. **Manual Testing**:
   - Send requests to both valid and fake paths.
   - Understand how invalid paths are handled.

2. **Start from Site Map**:
   - Use user-directed spider output as a base.

3. **Automate Requests**:
   - Use tools (e.g., Burp Intruder) with wordlists to:
     - Discover directories and files
     - Apply within known paths (`/auth/`, `/admin/`, etc.)

4. **Analyze Responses**:
   - Manually review response codes, headers, lengths.

5. **Recursive Enumeration**:
   - Repeat brute-force on newly discovered paths.

---

## 💡 Pro Tips
- Use **filtered views** in Burp Intruder to isolate interesting results.
- Build or modify **custom wordlists** based on app context.
- Try various privilege levels: anonymous, authenticated user, admin.
- Some apps may leak sensitive data via:
  - Response content
  - Redirect locations
  - Error messages

--- 

# 🧠 Inference from Published Content

## 📌 Overview
Many applications follow **naming conventions** that can be inferred from visible resources. By identifying patterns, you can **fine-tune your brute-force enumeration** to discover hidden content more effectively.

---

## 🔤 Naming Patterns and Style

- **EIS Example**: All resources under `/auth/` start with a **capital letter**.  
  → Use capitalized wordlists when brute-forcing in that directory.

- **Identified Page**:  
  - `/auth/ForgotPassword`  
  → Implies possible related paths like:
    - `/auth/ResetPassword`
    - `/auth/AddPassword`
    - `/auth/GetPassword`
    - `/auth/RetrievePassword`
    - `/auth/UpdatePassword`

---

## 🔢 Numeric Resource Inference

From spidering, resources like:
- `/pub/media/100`
- `/pub/media/117`
- `/pub/user/11`

...indicate that **other numeric IDs in range** may yield more valid pages.  
→ Brute-force incrementally (`100–200`, `1–50`, etc.)

---

## 🎯 Burp Intruder Customization

- Customize **any part of the HTTP request** to inject:
  - File prefixes (`Get`, `Add`, `Delete`)
  - Common verbs (`Create`, `View`, `Edit`)
- Example payloads:
  - `/auth/AddPassword`
  - `/auth/EditUser`
  - `/auth/DeleteAccount`

---

## 🪜 Hack Steps

1. **Collect All Enumerated Items**  
   - Gather all discovered directories, file names, extensions.

2. **Identify Naming Patterns**  
   - Examples:
     - `AddDocument.jsp`, `ViewDocument.jsp` → try `EditDocument.jsp`, `DeleteDocument.jsp`
     - Verbosity varies: `AddANewUser.asp`, `AddUser.asp`, `AddUsr.asp`, `AddU.asp`

3. **Identify Numeric/Date Patterns**  
   - Examples:
     - `AnnualReport2009.pdf`, `AnnualReport2010.pdf` → try `AnnualReport2011.pdf`
   - Real-world incident: journalists found unreleased financial data via predictable file names.

4. **Inspect Client-Side Code**
   - Look at:
     - HTML/JS comments
     - Disabled form buttons
     - Hidden input fields
     - `<!-- TODO: AdminConsole.jsp -->`
   - Check for server-side include references, back-end debug info, etc.

5. **Expand File Name and Extension Lists**
   - Add extensions:
     - `.txt`, `.bak`, `.old`, `.src`, `.inc`
     - Source code: `.java`, `.cs`, `.vb`, etc.

6. **Look for Temporary/Editor Artifacts**
   - Examples:
     - `.DS_Store` (Mac directory metadata)
     - `file.php~1`, `index.bak`, `main.php.swp`, `debug.log`, `.tmp`

7. **Combine Lists for Bruteforce**
   - Try all stems + extensions:
     - `Login.bak`, `ResetPassword.old`, `Admin.txt`
   - Try each file name as:
     - Subdirectory → `/ResetPassword/`
     - With multiple extensions → `file.old.bak`

8. **Focused Brute-Force on Patterns**
   - If `AddDocument.jsp`, `ViewDocument.jsp` exist:
     - Try: `EditDocument.jsp`, `DeleteDocument.jsp`
   - If `AddUser.jsp` exists:
     - Try: `AddAccount.jsp`, `AddFile.jsp`, `AddAdmin.jsp`

9. **Recursive Enumeration**
   - Each new discovery → input for another spidering/brute-force round.
   - Iterate until diminishing returns.

---

## 💡 Tooling Support

### 🔧 Burp Suite Pro – Content Discovery
- After mapping visible content:
  - Select Site Map branches → run content discovery.
- Techniques used:
  - Brute-force using built-in wordlists
  - Dynamic wordlist generation from known resources
  - Number/date-based extrapolation
  - Extension variation testing
  - Spidering from new discoveries
  - Response fingerprinting to reduce false positives

### 🔧 OWASP DirBuster
- Huge, frequency-ranked wordlists
- Useful for large-scale dictionary attacks on:
  - Directories
  - Common admin paths
  - Backup/config files

---

## 📌 Summary

| Target Area       | Example Techniques                                                                 |
|-------------------|-------------------------------------------------------------------------------------|
| `/auth/` paths    | Use verbs + "Password", e.g., `ResetPassword`, `UpdatePassword`                    |
| Numbered paths    | Brute-force ranges: `/user/1`, `/media/101`, etc.                                  |
| Patterned pages   | `ViewX.jsp`, `EditX.jsp`, `DeleteX.jsp` patterns                                    |
| Comments & HTML   | Look for clues in HTML comments, JS, and hidden form fields                        |
| File extensions   | Add `.bak`, `.inc`, `.java`, `.old`, `.log`, `.txt`                                 |
| Temp/Editor files | `.DS_Store`, `file.php~`, `index.php.swp`, `debug.log`                             |
| Tool Support      | Burp Suite Pro (content discovery), OWASP DirBuster                                |
