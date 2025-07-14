# Preventing SQL Injection

Despite its variations and complexities, **SQL injection is one of the easier vulnerabilities to prevent** — when done correctly. However, many widely used defenses are **only partially effective** or **misunderstood**.

---

## **Partially Effective Measures**

### **Escaping Single Quotes**
* Doubling `'` characters is a common workaround.
* Fails in the following scenarios:
  - **Numeric input**: Not enclosed in quotes, so escaping has no effect.
  - **Second-order SQLi**: Escaped input stored and re-used, restoring the original malicious structure.

### **Stored Procedures**
Often believed to prevent SQLi, but not foolproof:
* Stored procedures themselves can be vulnerable if **dynamic SQL** is constructed internally.
* Even safe procedures can be misused if **called with unsafe input**.

#### Example:
```sql
exec sp_RegisterUser 'joe', 'foo’; exec master..xp_cmdshell ...--'
```
* User input breaks query structure and chains malicious commands.
* Stored procedures don't inherently offer protection unless input is **sanitized or parameterized**.

---

## **Robust Defense: Parameterized Queries (Prepared Statements)**

Parameterized queries involve **two separate steps**:
1. Define the **SQL query structure** with placeholders (`?` or named parameters).
2. Bind **user-supplied values** to the placeholders.

Because query structure is already fixed in Step 1, **user input is always treated as data**, **not SQL code**.

---

### **Unsafe Dynamic Query (Vulnerable)**
```java
String queryText = "SELECT ename, sal FROM emp WHERE ename = '";
queryText += request.getParameter("name");
queryText += "'";
stmt = con.createStatement();
rs = stmt.executeQuery(queryText);
```

### **Safe Parameterized Version**
```java
String queryText = "SELECT ename, sal FROM emp WHERE ename = ?";
stmt = con.prepareStatement(queryText);
stmt.setString(1, request.getParameter("name"));
rs = stmt.executeQuery();
```

> ✅ Parameterization **fully separates query structure from input**.

---

## **Best Practices for Using Parameterized Queries**

1. **Use parameterization consistently** for **every** query.
   - Don’t rely on assumptions about which input is “safe.”
   - Avoid overlooking **second-order attacks** or assumptions made by different developers.

2. **Don’t mix parameterized and direct string concatenation**.
   - Even a single unparameterized field can reintroduce SQLi.

3. **Whitelist when user input affects query structure**, such as:
   - **Table/column names**
   - **SQL keywords** (e.g., `ORDER BY ASC|DESC`)
   - Parameter placeholders cannot handle these — use validated whitelist values or strict input sanitization (alphanumeric, no whitespace, max length).

---

## **Defense in Depth**

Even when parameterized queries are used correctly, **additional layers of protection** are essential to mitigate risks in case of failure.

### **1. Use Least Privilege Access**
* The application should access the database using the **minimum privileges necessary**.
* Avoid using accounts with DBA rights unless absolutely required.
* Consider separate database accounts for:
  - **Read-only** operations.
  - **Write operations**.
  - Access to sensitive tables (e.g., `users` vs `orders`).

> ✅ Segmentation ensures that a successful SQL injection vulnerability has **limited blast radius**.

### **2. Remove Unnecessary Database Functionality**
* Enterprise databases often include default features that can be misused.
* Disable or remove unused features and procedures.
* Even if attackers attempt to recreate them, this adds complexity and friction.

### **3. Apply Timely Security Patches**
* Regularly evaluate and apply vendor-issued patches.
* Subscribe to early notification services to receive alerts on vulnerabilities **before official patches**.
* Apply temporary mitigations or workarounds if a patch is not yet available.

---

## **Key Takeaways**

* **Escaping quotes and using stored procedures alone is not enough**.
* Only **proper parameterized queries** provide reliable, long-term protection.
* Enforce parameterization **everywhere**, regardless of perceived input safety.
* When user input must influence query structure, **strict whitelisting** is the safest route.
* Add **defense-in-depth layers**: least-privilege access, database hardening, and timely patching to further reduce risk.

---
