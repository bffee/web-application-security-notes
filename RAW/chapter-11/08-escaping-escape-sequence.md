## Example-08: Esacping from Escaping

> You escaped the dangerous characters, but forgot to escape the escape character itself.
> That’s like locking every door in your house… but leaving the key under the welcome mat.

---

## ⚙️ The Scenario

* App executes OS commands using user-controlled input (bad idea, but it happens).
* Developers **try to prevent command injection** by escaping metacharacters like:

```
; | & < > ' [space] [newline]
```

* They use a backslash (`\`) to escape these characters.
  For example:

  * `ls` → `\ls`
  * `;` → `\;`
* So far so good… *but* they forgot to escape the backslash itself.

---

## 💥 The Logic Flaw: Escape Character Not Escaped

### 💡 Quick Refresher:

In Unix-like shells, the backslash is the **escape character**.

* `\;` tells the shell: “Treat `;` as literal, not a command separator.”
* `\\` tells the shell: “I want to print an actual backslash.”

So what happens when input like this is submitted:

```
foo\;ls
```

Here’s the logic breakdown:

| Step  | What Happens                                                    |
| ----- | --------------------------------------------------------------- |
| **1** | App applies escaping → becomes `foo\\\;ls`                      |
| **2** | Shell interprets it as `foo\` (literal backslash) + `;ls`       |
| **3** | `;ls` is not escaped anymore → shell treats it as a new command |
| **4** | Result: `ls` is executed = 🧨 command injection                 |

---

## 🧪 HTB-Style Exploitation Mindset

### ✅ Hack Steps:

| Step | Action                                                                                                                       |           |
| ---- | ---------------------------------------------------------------------------------------------------------------------------- | --------- |
| 1.   | Identify places where user input reaches a shell command (e.g., ping, whois, grep, nslookup).                                |           |
| 2.   | Inject classic metacharacters: `;`, `&&`, \`                                                                                 | `, `\n\`. |
| 3.   | If those get escaped (e.g., `;` becomes `\;`), try to break escaping using **`\;`**, **`\\;`**, or even **double encoding**. |           |
| 4.   | Observe if your command runs — e.g., `; ls`, `; whoami`, \`                                                                  | id\`.     |
| 5.   | Bonus: Test **double escaping** → sometimes `\\` leads to single `\` in shell.                                               |           |

---

### 🐛 What They Missed

Developers escaped *bad characters*, but not the **thing doing the escaping**.

In secure escaping logic, you must **escape the escape** first.

Correct sequence:

1. Escape every existing `\` → becomes `\\`
2. Then escape other metacharacters → `;` → `\;`

Failing that leads to...

> **Escape Injection** — where the attacker undoes your escaping.

---

## 🔁 Bonus: JavaScript Variant

This logic flaw isn’t just for OS commands.

Here’s how it breaks JavaScript too:

**Insecure escaping example:**

```js
var name = '<%= escape(userInput) %>';
```

If `escape()` turns `'` into `\'`, but doesn’t escape the backslash…

### Input:

```
\';alert(1);// 
```

### Output:

```js
var name = '\';alert(1);//';
```

Boom: attacker breaks out of string and **injects a full script**.

This exact vulnerability was found in early versions of **Ruby on Rails** in the `escape_javascript()` function.

---

## 🧱 Developer Defense Strategy

| Mistake                           | Fix                                                                                              |
| --------------------------------- | ------------------------------------------------------------------------------------------------ |
| Not escaping the escape character | **Escape `\` first** before any others                                                           |
| Trusting custom sanitizers        | Use **built-in safe API** instead (e.g., `execFile` instead of `exec`)                           |
| Escaping instead of validating    | **Whitelist input formats** instead of escaping risky input                                      |
| Mixing concerns                   | Separate **data input** from **command logic** — don’t concatenate shell commands with user data |

---

## 🧠 Red Team Mentality

Any time you see:

* Escaping with backslashes
* Command-line functionality using user input
* JavaScript string injections
* CSV generation, PDF rendering, log parsing

…immediately think:

> **What if I undo their escaping by escaping the escape?**

That’s how you spot *“Escape from Escaping”* flaws.

