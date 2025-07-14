# Second-Order SQL Injection

**Second-order SQL injection** occurs when malicious input is initially **safely stored** in the database, but is later **retrieved and unsafely reused** in a SQL query, leading to injection.

This bypasses many filters because the injection payload is executed **not at the point of entry**, but **later during data usage**.

---

## **Vulnerability Pattern**

- Applications may correctly **sanitize input during INSERT** operations (e.g., doubling single quotes).
- But when **retrieving and reusing** that same data in later queries (e.g., UPDATE, SELECT), no further escaping is done.
- This makes it possible for previously “safe” input to **reintroduce SQL syntax** into a new query.

---

## **Example**

1. **Initial input is sanitized during registration**:
   ```sql
   INSERT INTO users (username, password, ID, privs) 
   VALUES ('foo''', 'secret', 2248, 1)
   ```

   - Username is `foo'`, and single quote is doubled (`'` → `''`) — *safe*.

2. **Later reused unsafely in a password change query**:
   ```sql
   SELECT password FROM users WHERE username = 'foo''
   ```

   - This query becomes **broken SQL** due to unescaped embedded single quote.
   - Results in:
     ```
     Unclosed quotation mark before the character string ‘foo
     ```

---

## **Attack Scenario**

1. **Attacker registers a crafted username**:
   ```sql
   ' or 1 in (select password from users where username='admin')--
   ```

2. **This is sanitized and stored safely**.
3. **Later reused in a query without re-sanitization**:
   ```sql
   SELECT password FROM users WHERE username = '' or 1 in (select password from users where username='admin')--'
   ```

   ➤ **Injected subquery is executed**.

4. **Error response discloses sensitive data**:
   ```
   Syntax error converting the varchar value ‘fme69’ to a column of data type int.
   ```

   ➤ Reveals the admin password `fme69`.

---

## **Key Takeaways**

- Second-order SQL injection is a **contextual, delayed vulnerability**.
- Occurs when:
  - Data is inserted safely,
  - Then later reused in a query **without sanitization**.
- Effective against **insert-filtering-only** defenses.
- Can expose **high-privilege actions** if reused in back-end processing.

---

## TIP

*Always apply contextual output encoding or sanitization at the point of **use**, not just at input. Sanitization must be **query-specific and location-aware**.*

---
