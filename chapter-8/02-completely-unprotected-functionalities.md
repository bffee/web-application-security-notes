# Completely Unprotected Functionality

In some applications, **sensitive features** (like admin panels) are accessible to **anyone who knows the URL**, regardless of user privileges — a critical access control failure.

---

## Weak or Nonexistent Protection

### **Example of an Exposed Admin Interface**
```
https://wahh-app.com/admin/
```
- Access control is purely **cosmetic** — only admin users see the link.
- But **no backend checks** stop unauthorized users from visiting the URL directly.

---

## Obscurity ≠ Security

### **Example of a "Hidden" URL**
```
https://wahh-app.com/menus/secure/ff457/DoAdminMenu2.jsp
```
- The only “protection” is that it’s **hard to guess**.
- This assumes attackers **won’t find it** — but that’s a flawed assumption.

> **MYTH**: “Low-privileged users won’t know the URL.”
> - URLs are **not secret**:
  - Visible on-screen
  - Stored in browser history, logs, bookmarks
  - Can be copied, emailed, or leaked
- Knowing a URL **does not mean** a user should be authorized to access it.

---

## Discovery via Client-Side Code

Attackers can uncover unlinked or hidden URLs by inspecting **JavaScript logic**, **HTML comments**, or **unused elements**.

### **Example: Admin UI Built Dynamically**
```javascript
var isAdmin = false;

if (isAdmin) {
  adminMenu.addItem("/menus/secure/ff457/addNewPortalUser2.jsp", "Create a new user");
}
```

- By reading the code, attackers can extract **hidden admin endpoints** even if they aren't shown in the UI.
- **Chapter 4** covers deeper content discovery techniques (e.g., JS inspection, comments, source analysis).

---

## Key Takeaway

> A functionality that is accessible **only by obscurity** (e.g., not linked, cryptic URLs) is **still vulnerable** if:
> - It lacks proper **backend access control checks**.
> - It can be reached by **non-privileged users** through direct requests.

---

## Summary

| Weak Practice                         | Why It's Dangerous                                      |
|--------------------------------------|----------------------------------------------------------|
| Cosmetic UI-based restrictions       | Can be bypassed by direct URL access                     |
| Cryptic or unlinked URLs             | URLs are not secrets — they can be found or shared       |
| Hidden links in JavaScript/HTML      | Easily discoverable via client-side code inspection      |
| No backend authorization checks      | Allows unauthorized access despite UI restrictions       |
