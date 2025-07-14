# Beyond SQL Injection: Escalating the Database Attack

Exploiting SQL injection often grants access to **all data** used by the application. However, this **should not be the end** of the attack.

Advanced attackers escalate further by:
* Compromising other applications (via shared DB)
* Gaining OS-level access
* Moving laterally within the internal network
* Setting up out-of-band channels
* Re-extending restricted database functionality

---

## **Why Escalate Beyond Data Access?**

- Applications often use **one DB account for all users** → compromise = total data access.
- **Shared DB environments** allow cross-application attacks.
- **DB servers are often trusted** and positioned deeper in the network → lateral movement becomes possible.
- DBs can serve as launch points for:
  * OS compromise
  * File manipulation
  * Network exfiltration
  * Remote access (e.g., reverse shells)

---

## **Debunking a Common Myth**

> *“Databases only need to defend against trusted internal users.”*

FALSE. Any vulnerability in the **application layer** allows **unauthenticated attackers** to act **with full privileges** of the application’s DB account.

---

## **MS-SQL**

### **xp_cmdshell** (available by default in older versions):
```sql
exec master..xp_cmdshell 'ipconfig > out.txt'
```

* Executes arbitrary **OS-level commands** via `cmd.exe`
* Runs as **LocalSystem** by default → full OS compromise
* Can be used for:
  - Data exfiltration
  - Malware/tool uploading
  - Creating backdoors

### **Registry access via**:
* `xp_regread`
* `xp_regwrite`

### **Re-enabling disabled xp_cmdshell**:
```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE WITH OVERRIDE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE WITH OVERRIDE;
```

---

## **Oracle**

### **Privilege Escalation via Built-in Packages**
* Many **built-in stored procedures** run with **DBA privileges**
* Vulnerabilities in these allow **injection inside PL/SQL**, escalating privileges

#### Example (before July 2006 patch):
```sql
SYS.DBMS_EXPORT_EXTENSION.GET_DOMAIN_INDEX_TABLES(...)
-- Injects: grant dba to public
```

### **Network Access / File I/O**
* `UTL_HTTP`, `UTL_INADDR`, `UTL_SMTP`, `UTL_TCP` – for out-of-band network connections
* `UTL_FILE` – read/write files on DB host

### **OS Command Execution (Java abuse)**
David Litchfield's 2010 method:
1. Exploit `DBMS_JVM_EXP_PERMS.TEMP_JAVA_POLICY`
2. Run OS commands with `DBMS_JAVA.RUNJAVA`
```sql
DBMS_JAVA.RUNJAVA('oracle/aurora/util/Wrapper c:\\...\\cmd.exe /c dir > C:\\OUT.LST')
```

### Resources:
* [Hacking Aurora](http://www.databasesecurity.com/HackingAurora.pdf)
* [BlackHat 2010](https://www.notsosecure.com/folder2/2010/08/02/blackhat-2010/)

---

## **MySQL**

### **Filesystem Access (FILE_PRIV)**

* `LOAD_FILE()` – Read arbitrary files:
```sql
SELECT LOAD_FILE('/etc/passwd')
```

* `SELECT ... INTO OUTFILE` – Write to filesystem:
```sql
SELECT * FROM users INTO OUTFILE '/tmp/dump.txt'
```

* Can bypass MySQL's internal access controls by directly reading **MyISAM** files (stored in plaintext).

### **User-Defined Functions (UDF)**

* Custom functions can call **external libraries**
* Attacker writes a **malicious binary library** and registers it as a function:
  - Must be placed in MySQL’s **plugin load path**
  - Refer to: Chris Anley’s paper *Hackproofing MySQL*

---

## **Key Takeaways**

- SQLi is a **starting point**, not the finish line.
- **DBs should be hardened** against both unauthenticated and authenticated attackers.
- Every major DB platform has methods to:
  - Escalate to OS
  - Extend DB functionality
  - Bypass internal controls
- Keep DBs **patched**, **minimally privileged**, and **monitored**.

---
