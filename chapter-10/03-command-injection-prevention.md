# Preventing OS Command Injection

---

### General Principle

- **Avoid direct OS command execution**.
  - Almost all required tasks can be done via safe, built-in APIs.
  - These APIs do not allow unintended command execution and are not vulnerable to metacharacter injection.

---

### If Direct Execution Is Unavoidable

**Input Restrictions:**

- **Use a whitelist** of expected values wherever possible.
- If a full whitelist is not viable:
  - Restrict input to a **narrow character set** (e.g., alphanumeric only).
  - Reject any input containing **metacharacters**, **whitespace**, or any other unsafe character.

**Safer Command APIs:**

- Use APIs that do **not invoke a shell interpreter**, such as:
  - `Runtime.exec` (Java)
  - `Process.Start` (ASP.NET)

> These APIs take command and argument(s) separately and do not process shell metacharacters, making chaining and redirection impossible.

See Chapter 19 for a detailed breakdown of secure execution APIs.

---

# Preventing Script Injection Vulnerabilities

---

### General Principle

- **Do not pass user input to dynamic execution or inclusion functions**.
  - Avoid functions like `eval`, `Execute`, or `include` with data derived from user input.

---

### If Dynamic Execution Is Unavoidable

- **Use a strict whitelist** of safe, expected values.
- If not feasible:
  - Enforce a character-level filter that permits only **harmless characters**, such as:
    - Alphanumerics only
    - No whitespace
    - No special characters

---

### Summary

> Prevention of both OS command and script injection revolves around two core ideas:
> - **Avoid dangerous features** (direct shell execution, dynamic code eval).
> - **Strictly validate and sanitize input** using whitelists and restricted character sets when these features must be used.

