# Identifier-Based Functions

Many applications control access to resources using **identifiers passed as request parameters** (e.g., in the URL or POST body). If access controls are not properly enforced, this allows attackers to **manipulate identifiers** and gain unauthorized access to data or functions.

---

## How It Works

- Resource identifiers (e.g., document IDs) are submitted in client requests:
  ```
  https://wahh-app.com/ViewDocument.php?docid=1280149120
  ```
- The link is shown only to the document’s owner.
- But if no server-side access check is in place, **any authenticated user can access it**, if they know or guess the `docid`.

---

## Common Causes

- **Cross-system integration issues**:
  - When interfacing with external components or legacy systems, session-based access models may break.
  - Developers may fallback to using identifiers passed by the client to make access decisions.

> TIP: Never trust client-supplied identifiers for making access control decisions, especially when the backend system has no session awareness.

---

## Identifier Predictability

- **Secure identifiers**:
  - Randomly generated GUIDs or cryptographically strong tokens.
- **Insecure identifiers**:
  - Sequential IDs, timestamps, or user IDs — **easy to guess**.

> Even if identifiers are unpredictable, if no authorization checks are made, the vulnerability still exists.

---

## Attack Vectors

- **Manual probing**: Guess or iterate over identifiers.
- **Leak discovery**: Use application logs, debug output, or UI features that disclose identifiers.
- **Function abuse**: IDs may also refer to internal **function names**, allowing privilege escalation through function-level access.

> TIP: Application logs are a **gold mine**. Look for values like usernames, doc IDs, account numbers, etc., to target identifier-based access mechanisms.

---

## Function Parameter Misuse

- Identifiers aren’t just for resources — they may point to **functions** too:
  ```
  /Controller.php?op=deleteUser
  ```
- If authorization depends on hiding these from the UI rather than verifying on the server, **function-level access control is broken**.

---

## Summary

| Risk Area                   | Description                                                   |
|----------------------------|---------------------------------------------------------------|
| Weak identifier validation | Users can access unauthorized resources by changing parameters |
| Guessable identifiers      | Sequential or timestamp-based IDs ease brute-force attacks    |
| Function ID exposure       | Sensitive operations triggered via exposed function names      |
| Cross-system shortcuts     | External components skipping session-based access control      |
