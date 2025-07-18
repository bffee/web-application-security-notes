# Manipulating File Paths

Many web applications accept **user-supplied input as file or directory names**, which are then passed to file-handling APIs. If these inputs are **not properly validated**, it can lead to serious vulnerabilities such as:

- **Path Traversal** – accessing unintended files or directories.
- **File Inclusion** – executing or displaying unauthorized files.

These issues arise when developers trust the input without performing thorough validation or sanitization.

---

## Path Traversal Vulnerabilities

### Core Concept

- Path traversal occurs when **user input is used to construct file paths** in an unsafe way.
- Attackers can inject **directory traversal sequences (`../`)** to:
  - Read arbitrary files.
  - Overwrite sensitive files.
  - In some cases, even execute commands if critical files are altered.

---

### Real-World Example

**Request:**
```
http://mdsec.net/filestore/8/GetFile.ashx?filename=keira.jpg
```

**Server Behavior:**

1. Extract `filename=keira.jpg`.
2. Append to prefix path: `C:\filestore\`.
3. Construct full path: `C:\filestore\keira.jpg`.
4. Read file content and return to client.

---

### Path Traversal Attack

**Malicious Input:**
```
filename=..\windows\win.ini
```

**Resulting Path:**
```
C:\filestore\..\windows\win.ini → C:\windows\win.ini
```

> Instead of an image file, a Windows configuration file is returned.

---

### Security Implications

- **Read access**: Attackers can obtain sensitive configuration files.
- **Write access** (rare but possible): Attackers can tamper with log files, scripts, or scheduled tasks to escalate privileges or execute arbitrary code.
- Severity depends on the **permissions of the application’s user context**.

> ❗ **Historical Note**: Older versions of Windows IIS ran with **LocalSystem** privileges, granting full file system access. While modern servers use restricted accounts, `c:\windows\win.ini` remains a common target because it is universally readable.

---

### Application Defenses

- Many applications use **input validation filters** to block traversal attempts.
- However, these are often **incomplete** and can be bypassed using:
  - Encoded traversal (`..%2f`)
  - Repeated traversal (`....//`)
  - Mixed slashes (`..\../`)

> Simple string filtering is insufficient. Applications must perform **secure canonicalization** and **normalize paths** before any file operations.
