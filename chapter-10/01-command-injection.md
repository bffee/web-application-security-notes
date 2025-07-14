# Attacking Back-End Components

Web applications often act as the interface to back-end components such as web services, databases, mail servers, filesystems, or the operating system. These components can interpret data differently, introducing new vulnerabilities when user input is passed to them. A flaw here can lead to unauthorized data access, arbitrary code execution, or full system compromise.

---

## Injecting OS Commands

**Command Injection** occurs when user input is passed to a system shell command without proper validation or sanitization. It allows attackers to modify or append OS commands, which run in the context of the web server.

### Common Causes
* Developers use system-level functions (`exec`, `system`, `shell_exec`, `Process.Start`, etc.) for convenience or performance.
* Lack of proper sanitization allows shell metacharacters (e.g., `|`, `&`, `;`, `&&`) to alter command execution.

---

### Example 1: Perl Injection
```perl
my $command = "du -h --exclude php* /var/www/html";
$command = $command.param("dir");
$command = `$command`;
```
* User-supplied input is directly appended to a shell command.
* Supplying `| cat /etc/passwd` as input leads to execution of an arbitrary command.

---

### Example 2: ASP (C#) Injection
```csharp
string dirName = "C:\\filestore\\" + Directory.Text;
ProcessStartInfo psInfo = new ProcessStartInfo("cmd", "/c dir " + dirName);
Process proc = Process.Start(psInfo);
```
* Supplying `& whoami` causes both `dir` and `whoami` to execute.

---

## Injecting Through Dynamic Execution

Some languages (like PHP, Perl, and ASP) support **dynamic code execution** where strings are treated as executable code.

### Example: PHP Eval Injection
```php
$storedsearch = $_GET['storedsearch'];
eval("$storedsearch;");
```
* URL: `/search.php?storedsearch=\$mysearch=wahh;%20system('cat%20/etc/passwd')`
* Results in execution of `system('cat /etc/passwd')`

---

### Key Risks of Dynamic Execution
* Arbitrary command execution.
* Full control over server-side logic.
* Exfiltration of sensitive files or credentials.

---

**NOTE**: 
* Perl’s `eval` is vulnerable in the same way.
* Classic ASP uses `Execute()`.
* The `;` character may need to be URL-encoded as `%3b` to avoid premature parameter termination in CGI scripts.

---
