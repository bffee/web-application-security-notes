# Static Files

Access control vulnerabilities can arise when **protected resources** are exposed as **static files** directly served from the web server, bypassing application logic.

---

## Core Issue

- Static files (e.g., PDFs, images, logs) are served **directly** by the web server.
- **No application logic** is executed → **no access control checks**.
- If users can guess or learn the URL, they can access the resource **without authorization**.

---

## Example: Ebook Downloads

An online bookstore allows ebook downloads after purchase:

```
https://wahh-books.com/download/9780636628104.pdf
```

- PDF is directly accessible if the user knows the ISBN.
- Static resources often follow **predictable patterns**:
  - Sequential document IDs
  - Public identifiers (ISBN, user IDs, report years)

> 🔓 An attacker can enumerate URLs and download **all available files** — even those they haven't purchased.

---

## High-Risk Scenarios

This vulnerability is especially prevalent in:

- **Ebook and content platforms** (books, videos, reports)
- **Financial applications** (annual reports, client statements)
- **Software distribution portals** (setup binaries, update files)
- **Admin panels** (logs, internal exports, configuration dumps)

---

## Why It Happens

- Developers assume static files are safe because they are:
  - Only linked after certain actions (e.g., payment).
  - Not exposed via the UI for unauthorized users.

> ❗ Just hiding or obfuscating URLs is **not** a substitute for real access controls.

---

## Mitigation Strategies

- **Move static files behind dynamic access endpoints**:
  - Route requests through server-side code that performs access checks.
- **Use per-user, expiring links** (e.g., signed URLs with short TTL).
- **Store files outside the web root**:
  - Serve only after verifying permissions.

---

## Summary

| Issue                              | Risk                                                      |
|------------------------------------|-----------------------------------------------------------|
| Direct access to static files      | Bypasses authentication and authorization checks          |
| Predictable URLs                   | Enables mass unauthorized downloads                       |
| Files inside web root              | Publicly accessible unless explicitly protected           |
| No application code execution      | Can't enforce access control on request                   |
