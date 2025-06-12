# 🌐 Leveraging the Web Server

## 📌 Overview
Web servers and application servers may contain **vulnerabilities or default content** that expose **unlinked resources**, aiding in application discovery or attack planning.

---

## 🧱 Web Server-Level Vulnerabilities

- Bugs in web server software may allow:
  - **Directory listing** (e.g., auto-indexing)
  - **Viewing raw source code** of dynamic pages (e.g., `.php`, `.jsp`)
- These bugs can expose **hidden or unlinked files/pages**.
- See **Chapter 18** for exploitation techniques.

---

## ⚙️ Default Content & Third-Party Components

- Application servers often ship with:
  - **Sample scripts**
  - **Diagnostic pages**
  - These may be vulnerable or leak sensitive data.

- Many apps use **third-party components**:
  - Shopping carts
  - Forums
  - CMS modules
- These are usually installed at **predictable locations** (e.g., `/phpmyadmin/`, `/admin/`, `/cms/`).

---

## 🤖 Tool-Based Discovery

### 🔧 Tools like Nikto, Wikto
- Use **large databases** of known default directories, files, and third-party apps.
- Can identify:
  - Default content
  - Unlinked resources
  - Known vulnerable software components

#### ✅ Example: Wikto Usage
- Detected: `/phpmyadmin/` (default install path)
- Found vulnerable app page: `/gb/index.php?login=true` (used by gbook, known vuln)

> ⚠️ Tools like Wikto & Nikto often **miss custom functionality** and produce:
> - **False positives** (non-vulnerable items flagged)
> - **False negatives** (miss content due to server config, custom error handling, or nonstandard directories)

---

## 📉 Tool Limitations

| Limitation                   | Description                                                                 |
|-----------------------------|-----------------------------------------------------------------------------|
| Redundant Checks            | Many tests overlap or are outdated                                          |
| False Positives             | May report a vulnerability that doesn't exist                              |
| False Negatives             | May miss things if:                                                         |
|                             | - Custom error pages don’t return 404                                       |
|                             | - Directories/scripts are renamed or moved                                  |
|                             | - HTTP response codes are customized                                        |
| Misinterpreting Virtual Hosts | If scanning by IP, domain links may be treated as offsite                  |

> ✅ **Burp Intruder** is recommended for more control:
> - Allows manual interpretation of responses
> - Doesn't rely on automated issue verification

---

## 🪜 Hack Steps – Using Nikto

1. **Custom Directory Paths**  
   - If the app uses a non-standard location (e.g., `/cgi/cgi-bin`), use:  
     `--root /cgi/`  
     or for CGI:  
     `--Cgidirs /cgi/cgi-bin/`

2. **Custom 404 Page Handling**  
   - If the server uses a custom error page **without** returning HTTP 404:  
     Use `--404 "<known string in the custom error page>"`  
     to help Nikto recognize it.

3. **Manual Validation**  
   - Nikto does **not verify** findings. Always:
     - Manually confirm flagged resources.
     - Inspect raw HTTP responses yourself.

4. **Hostname Awareness**
   - Avoid scanning by **IP only** unless necessary.
   - If using IP, tools may ignore domain-based links (common in virtual hosting).

---

## 🧠 Summary

| Technique/Tool     | Purpose                                  | Limitations                              |
|--------------------|-------------------------------------------|-------------------------------------------|
| Web server bugs     | May allow full directory or source listing | Rare but critical when found              |
| Default content     | Sample, diagnostic, or 3rd-party apps     | Often vulnerable if left enabled          |
| Nikto/Wikto         | Discover known paths, components, vulns   | False positives/negatives; no custom detection |
| Burp Intruder       | Manual probing and analysis               | Slower, but more precise                  |

