# Finding SQL Injection Bugs

SQL injection vulnerabilities can range from glaringly obvious to extremely subtle:

* Some are detected with a single crafted input.
* Others mimic benign anomalies or resemble unrelated vulnerabilities.
* Regardless of their detectability, all inputs **must be tested systematically**.

---

### NOTE

During your application mapping (see Chapter 4), you should have flagged areas where the application appears to interact with a back-end database. These are your **primary targets**.

However, even data not visibly tied to database interaction can be handled unsafely. You must **probe all inputs**, including:

* **URL parameters**
* **Cookies**
* **POST data**
* **HTTP headers**

> Test **both the names and values** of these parameters for SQL injection.

---

### TIP

If the application uses a **multistage process** (e.g. wizards, carts, forms across multiple steps), SQL queries may be performed **only at the end** of the process. Be sure to **complete the workflow** before judging whether a vulnerability exists.

---

## 1. Injecting into String Data

When user input is placed into SQL **string contexts**, it is usually enclosed in single quotes (`'value'`). To break this structure and inject SQL logic, you must escape or terminate the string.

---

### HACK STEPS

*These are the ordered steps for identifying SQL injection vulnerabilities involving string-based parameters:*

- **Step 1: Submit a single quote `'`**
  * Observe if the application produces an error or behaves differently.
  * If a detailed error message appears, consult the **SQL Syntax and Error Reference** section later in the chapter to analyze the message.

- **Step 2: Submit two single quotes `''`**
  * This is interpreted as a literal single quote by the database.
  * If this removes the error from step 1, it's likely that the input is indeed inside a SQL string — a good indicator of SQL injection.

- **Step 3: Try string concatenation**
  * Construct inputs that resolve to benign values using SQL string operators.
  * If the application treats your input as equivalent to the normal string (e.g., "FOO"), then injection is probably possible.

  *Examples of string concatenation per DBMS:*
  * **Oracle**: `'FOO'||'BAR'`
  * **MS-SQL**: `'FOO' + 'BAR'`
  * **MySQL**: `'FOO' 'BAR'` (note: space between quotes)

---

### TIP

You can use the SQL wildcard `%` in a search field to check if the application passes your input into a SQL query. If a large number of results is returned, it's a hint that backend querying is occurring — though this **does not confirm** a vulnerability by itself.

---

### TIP

Submitting a single quote can sometimes cause **JavaScript errors** in the browser. This occurs if your input is echoed back into a script block without proper encoding.

* This may signal a **cross-site scripting (XSS)** vulnerability.
* It also confirms that your input flows through untrusted sinks, increasing the risk of **combined injection flaws**.

---

## 2. Injecting into Numeric Data

While numeric input is often passed **directly** into SQL queries without being enclosed in quotes, it may still be handled as string data. Hence, you should **always begin by following the string injection tests**. If no vulnerabilities are found, you can apply additional techniques that specifically target numeric contexts.

---

### HACK STEPS

*These steps help identify SQL injection vulnerabilities in numeric parameters:*

- **Step 1: Submit an equivalent mathematical expression**
  * Replace a numeric input with an expression that evaluates to the same value.
    - Example: For `2`, try `1+1` or `3-1`.
  * If the application behaves identically, it may be vulnerable.

- **Step 2: Focus on parameters that affect visible behavior**
  * For instance, if a `PageID=2` loads a particular page, and `PageID=1+1` produces the same result, this strongly indicates injection.
  * However, if modifying the input causes **no visible change**, this test cannot confirm or deny a vulnerability.

- **Step 3: Use SQL-specific functions for further validation**
  * Inject more advanced expressions that invoke SQL functions.
    - Example: `67 - ASCII('A')` is equivalent to `2` (since ASCII of `'A'` is `65`).
  * These function calls only work if the server accepts quoted input.

- **Step 4: Avoid quotes by coercing strings into numbers**
  * If quotes are filtered, use unquoted string characters, relying on implicit type conversion:
    - Example: `51 - ASCII(1)` yields `2` (ASCII of `'1'` is `49`).

---

### TIP: URL-Encoding Special Characters

When testing SQL injection via HTTP requests, you must **encode special characters** to ensure they are correctly interpreted by the server:

* `&` → `%26`
* `=` → `%3d`
* Literal space → `+` or `%20`
* `+` → `%2b` (useful when submitting expressions like `1+1`)
* `;` → `%3b` (important when targeting cookies)

> Failing to encode properly may cause the request to break or deliver unintended input.

---

Most SQL injection flaws — even those that don’t return visible results or detailed errors — can be detected using the above methods. However, if standard probing fails, **more advanced techniques**, such as **time-based testing**, may be necessary. These will be covered later in this chapter.


---

## 3. Injecting into the Query Structure

In some situations, **user-supplied input is embedded directly into the structure of a SQL query**, not as data but as part of the query syntax. When this occurs, **no escaping or breaking out of a string context is necessary** — the attacker can directly provide valid SQL syntax.

---

### Key Concept

The most common structural injection point is in the `ORDER BY` clause, where users can specify:
- Column names
- Column positions
- Sort direction (e.g., `ASC` or `DESC`)

Since these values are not enclosed in quotes, **traditional defenses like quote escaping or prepared statements do not apply**, making this a subtle and dangerous vector.

---

### Real-World Example

Suppose an application executes the following SQL query:

```sql
SELECT author, title, year FROM books WHERE publisher = 'Wiley' ORDER BY title ASC
```

If the user controls the `title` portion, they may inject arbitrary column names or SQL expressions — without needing to use quotes or special escape characters.

---

### TIP

*Other structural injection points may also exist:*

- **Column names** used in `WHERE` clauses
- **Table names** (rare, but possible)
- **Sort order** (`ASC` or `DESC`) exposed directly to the user

Many applications incorrectly assume these elements are safe because they don’t involve string data — but they are not immune to SQL injection.

---

### Detection Challenges

Finding injection in query structure is difficult because:
- Invalid inputs often lead to **generic SQL errors**.
- Responses may not differ meaningfully between valid and invalid input.
- Automated fuzzing tools often overlook these cases because standard payloads won’t work.

---

### NOTE

Prepared statements and quote escaping offer **no protection** in structural injection contexts. Applications using these defenses elsewhere may still be vulnerable here — making this vector especially important in modern apps.

---

### HACK STEPS

*Follow these steps to probe for structural SQL injection:*

- **Identify any input controlling result order or fields:**
  * Look for parameters that affect sorting or column display in output tables.

- **Test numeric-based sorting inputs:**
  * Try inputting increasing numeric values:
    - Example: `?sort=1`, `?sort=2`, `?sort=3`, etc.
    - Behavior:
      - `ORDER BY 1` sorts by the first column,
      - `ORDER BY 2` sorts by the second column.
      - If the input exceeds the number of columns, the query should fail.
  
  * Try switching sort direction to validate injection:
    - Examples:
      - `1 ASC --`
      - `1 DESC --`
    - If the result order changes accordingly, your input is likely injected directly into the `ORDER BY` clause.

- **Test for column injection using literals:**
  * Submit a literal (e.g., `1`) and observe output. If a column with `1` in every row appears, the input may be part of the `SELECT` clause itself:
    ```sql
    SELECT 1, title, year FROM books WHERE publisher = 'Wiley'
    ```

---

### NOTE

Exploiting `ORDER BY` injection is fundamentally different:

- You **cannot inject** keywords like `UNION`, `WHERE`, `OR`, or `AND` directly.
- Instead, use **nested queries or subselects**:
  - Example:
    ```sql
    ORDER BY (SELECT 1 WHERE <<condition>> OR 1/0=0)
    ```

- In **MS-SQL**, you can also leverage **query batching**, making this injection point highly exploitable under the right conditions.

```sql
ORDER BY 1; SELECT sensitive_data FROM users;--
```

> These techniques will be expanded further in the **inference-based SQLi** section later in the chapter.
