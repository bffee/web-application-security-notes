# Using SQL Exploitation Tools

Many SQL injection techniques involve **manually extracting small amounts of data** through numerous requests. To simplify this, various tools exist that:

* Automate detection and exploitation
* Handle DB-specific syntax
* Optimize payloads for faster and stealthier attacks

---

## **Common Workflow of SQLi Tools**

1. **Brute-force parameters** to locate injection points
2. **Identify vulnerable fields** by injecting characters like:
   * `'`, `)`, `--`, SQL keywords, etc.
3. Attempt **UNION-based injection**:
   * Brute-force column count
   * Find a **`varchar`-compatible column** for data retrieval
4. Use **custom queries** (if possible):
   * Concatenate multiple values to return them through a single column
5. If UNION fails:
   * Use **Boolean-based conditions**: `AND 1=1`, `AND 1=2`
6. If Boolean-based injection fails:
   * Use **time delays**: exploit response time differences to infer data

---

## **Tool Capabilities**

* Query **metadata tables** to discover schema
* Leverage **built-in DB functions** (e.g., `xp_cmdshell`)
* Use **optimizations**:
  - Avoid filters
  - Reduce total requests (inference optimizations)
  - Bypass quote restrictions

---

> ⚠️ These tools are **not magic bullets**. They require:
> - Pre-existing knowledge of the vulnerability
> - Correct **placement of quotes**, **comments**, and **syntax**
> - Sometimes **manual tuning** of prefix/suffix wrappers

---

## **HACK STEPS**

### Step 1: Monitor with Proxy
* Intercept requests
* Use **verbose/debug mode**
* Correlate injected payloads with app behavior

---

### Step 2: Adjust Syntax

Sometimes necessary to:
* Add **comment characters** (`--`, `#`)
* Balance quotes: `' or 1=1--`
* Match parenthesis or **query structure**

---

### Step 3: Use Nested Subqueries

If syntax keeps failing, isolate the injection to a **controlled nested query**:

* **Oracle**:
  ```sql
  '||(SELECT 1 FROM dual WHERE 1=[input])
  ```

* **MS-SQL**:
  ```sql
  (SELECT 1 WHERE 1=[input])
  ```

Works well for **inference-based attacks**, especially in:
* `SELECT`, `UPDATE`, and in Oracle, also `INSERT` statements

---

## **sqlmap: The Recommended Tool**

* Supports:
  - **MySQL**, **Oracle**, **MS-SQL**, and others
  - **Union-based**, **error-based**, **Boolean**, **time-delay**
  - **OS-level escalation** (e.g., `xp_cmdshell`)
  - **File read/write**
* Best used with:
  ```bash
  --sql-shell
  ```

### Example Usage:
```bash
sqlmap.py -u http://wahh-app.com/employees?Empno=7369 --union-use --sql-shell -p Empno
```

### Sample Output Walkthrough:
* Detects injectable param: `Empno`
* Confirms backend DBMS: **Oracle**
* Finds UNION-compatible injection
* Opens interactive SQL shell:
```sql
sql-shell> select banner from v$version
```

**Output:**
```
[*] Oracle9i Enterprise Edition Release 9.2.0.1.0 - Production
[*] PL/SQL Release 9.2.0.1.0 - Production
[*] TNS for 32-bit Windows: Version 9.2.0.1.0 - Production
...
```

---

## **Key Takeaways**

* SQLi tools are **exploitation tools**, not discovery tools.
* They require **manual setup** and understanding of injection context.
* Tools like **sqlmap** are versatile and powerful, especially with blind or complex injections.
* Properly using these tools can **save time**, **maximize data extraction**, and **enable privilege escalation**.

---
