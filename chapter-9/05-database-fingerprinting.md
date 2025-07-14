# Fingerprinting the Database

While basic SQL injection techniques often work across multiple database platforms, **advanced exploitation increasingly depends on platform-specific behavior**. Accurately fingerprinting the back-end database becomes critical for tailoring your attack strategy.

---

## Why Fingerprint?

*Different databases*:
- Use **different syntax** for string operations and functions.
- Offer **unique features**, global variables, and error behaviors.
- Respond differently to edge cases and malformed queries.

Identifying the DBMS lets you:
- Choose correct concatenation methods.
- Craft payloads with appropriate functions and operators.
- Exploit version-specific behaviors or features.

---

## Methods of Fingerprinting

### **1. String Concatenation Test**  
Inject test strings using known concatenation syntax for different databases. If the query returns the expected value, it likely reveals the database type:

- **Oracle**: `'serv'||'ices'`
- **MS-SQL**: `'serv'+'ices'`
- **MySQL**: `'serv' 'ices'` *(Note: the space)*

> Inject each of these in place of a string and compare the outputs.

---

### **2. Numeric Expression Errors**  
Use expressions that evaluate to `0` in one platform but throw an error in others:

- **Oracle**: `BITAND(1,1) - BITAND(1,1)`
- **MS-SQL**: `@@PACK_RECEIVED - @@PACK_RECEIVED`
- **MySQL**: `CONNECTION_ID() - CONNECTION_ID()`

If the query executes silently, it indicates the expected platform. If it throws a syntax or function error, you're likely on a different DBMS.

---

### **3. Inline Comments (MySQL-Specific)**  
MySQL has a unique feature for version-dependent execution using comment syntax:

```sql
/*!32302 AND 1=0*/
```

- If the version of MySQL is **≥ 3.23.02**, the above behaves like `AND 1=0`.
- Otherwise, it's treated as a comment and ignored.
- This allows for **precise version fingerprinting**.

> Much like C-style preprocessor directives, this lets attackers (or developers) conditionally execute logic based on the MySQL version.

---

## NOTE

- **MS-SQL and Sybase**: These platforms are very similar and share stored procedures, system tables, and variables. Most attacks developed for MS-SQL will also apply to Sybase.
- **String concatenation** and **inline comments** are generally safer methods for blind fingerprinting, especially when full error messages are not visible.

---

## TIP

When fingerprinting, always validate results across multiple payloads. A single successful behavior might have alternative explanations, so use **at least two independent confirmation vectors**.

```sql
-- Example attack chain:
1+1 → 2      ✅
'1' + '1'    → 11 on MSSQL, fails on Oracle
@@VERSION    → Present only on MS-SQL
/*!40101*/   → MySQL version-based execution
```
