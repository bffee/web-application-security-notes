# Testing with Limited Access

When you only have access to a **low-privileged account** (or no login credentials at all), comprehensive access control testing becomes more challenging — but not impossible. With a strategic approach, you can uncover misconfigured or forgotten sensitive functionalities, even without privileged access.

---

## Discovering Hidden Functionality

Some protected features may not be linked anywhere in the UI — they may be **legacy features**, **admin-only tools**, or **new features not yet published**.

### Hack Steps

1. **Perform Content Discovery**  
   Use the techniques from Chapter 4 (e.g., spidering, brute-forcing paths) to enumerate all application content. Even a low-privileged user can often:
   - Discover sensitive or hidden pages.
   - Directly access unprotected functionality.

2. **Guess Role-Based Parameters**  
   Modify URLs and POST data by adding parameters like `admin=true`. Some apps expose functionality conditionally using query string flags.

3. **Test for Referer-Based Controls**  
   - Remove or modify the `Referer` header for requests.
   - If access is blocked without a valid `Referer`, the app is relying on this insecure header for authorization.
   - Burp Scanner will attempt this automatically and flag such cases.

4. **Review Client-Side Code Thoroughly**  
   - Look for hidden links, dynamic menus, or UI elements generated in JavaScript based on user role.
   - Examine HTML comments or source for clues.
   - Decompile browser extensions (see Chapter 5) to extract hidden server endpoints.

---

## Testing Resource Access

Once hidden or poorly protected functionality is discovered, test whether **horizontal access controls** are enforced properly.

### Hack Steps

1. **Look for User-Specific Identifiers**  
   Identify parameters like document IDs, account numbers, etc., used to fetch resources.

2. **Analyze Identifier Patterns**  
   - Create multiple objects (e.g., orders, messages) to generate new identifiers.
   - Look for predictable sequences (e.g., incrementing IDs).

3. **Guess Other Identifiers**  
   - If identifiers are numeric or sequential, try nearby or random numbers.
   - If identifiers are GUIDs or hashes, guessing may be impractical, but not impossible if clues exist elsewhere (logs, error messages).

4. **Mount Automated Attacks**  
   - If resource IDs are predictable and access control is missing, use **Burp Intruder** or a custom script (see Chapter 14) to:
     - Harvest personal data
     - Extract documents or user credentials
     - Scan for admin-level accounts

---

## Real-World Exploitation Example

- A vulnerable **Account Info page** displays a user’s personal details along with their **masked password**, but still transmits the full password in the response body.
- If IDs are sequential and access control is broken:
  - Launch an Intruder attack with user IDs in range.
  - Harvest usernames and passwords of all users, including administrators.


---

## Privilege Escalation via Harvested Accounts

Once an access control flaw is found:

> 🎯 Attempt vertical privilege escalation.

- Admins are often the **earliest registered users** → try low user IDs first.
- If manual login is infeasible:
  - Write a script to test all credentials.
  - Access each account's **home page**.
  - Admins may see more content or have access to all user pages.

---

## TIP

> When harvesting many user credentials, **automatically identify admin accounts**:
>
> - Admins may have special dashboards or see more user data.
> - Login as each user and load their homepage to identify elevated privileges.
> - Script the process to scale your attack efficiently.

---
