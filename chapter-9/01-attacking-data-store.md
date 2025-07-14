# Attacking Data Stores

Nearly all web applications depend on data stores that hold core logic and critical data like user accounts, permissions, and configurations. Vulnerabilities in how applications interact with these stores can allow attackers to bypass access controls, especially when:

* A common privilege level is used for all users when accessing the data store.
* Application logic is built around querying/modifying the store directly.

---

## Injecting into Interpreted Contexts

**Interpreted languages** process code at runtime. If user-supplied data is inserted unsafely into code executed by these interpreters, code injection vulnerabilities arise.

**Common interpreted languages used in web apps:**
* SQL
* LDAP
* Perl
* PHP

**Key vulnerability:**
* User input breaks out of the data context into code context and is interpreted as executable logic.

> In contrast, compiled languages execute precompiled machine code. Injection in such systems involves different techniques (see Chapter 16).

---

## Bypassing a Login via SQL Injection

A typical login function using SQL:

```sql
SELECT * FROM users WHERE username = 'marcus' AND password = 'secret'
```

### Exploit: Injecting into `username` field

If attacker supplies:
`admin'--`

Resulting query:
```sql
SELECT * FROM users WHERE username = 'admin'--' AND password = 'foo'
```

This is effectively:
```sql
SELECT * FROM users WHERE username = 'admin'
```
*Password check is bypassed.*

### Exploit: Guessing admin account

If attacker supplies:
`' OR 1=1--`

Query becomes:
```sql
SELECT * FROM users WHERE username = '' OR 1=1
```

*Returns all rows. The application usually logs in the first user — typically the administrator.*

---

### NOTE

This type of **interpreted context injection** applies beyond SQL:

* LDAP
* XPath
* Message queues
* Custom interpreted query formats

---

## HACK STEPS: Detecting and Exploiting Injection Vulnerabilities

**1. Supply unexpected syntax:**  
  * Begin with simple test payloads that include control characters or operators used by the interpreted language (e.g., `'`, `"`, `--`, `#`, `)`, `||`, `OR 1=1`).

**2. Analyze application responses:**  
  * Look for anomalies such as unanticipated behavior, error pages, or different HTTP statuses that might suggest the interpreter is struggling with malformed queries.

**3. Examine server error messages:**  
  * These can reveal back-end query fragments, function names, or even full queries. Use these clues to craft better payloads.

**4. Refine and iterate your inputs:**  
  * If you suspect injection but the results are inconclusive, systematically try variants — changing quote styles, escaping techniques, or clause structures — to provoke clearer evidence.

**5. Create a proof-of-concept:**  
  * Construct a test that verifies execution. For example, bypass login, retrieve a known value, or return a string literal in the response.

**6. Exploit the interpreter’s capabilities:**  
  * Once injection is confirmed, use features of the language (e.g., SQL’s `UNION SELECT`, `INSERT`, or `UPDATE`) to perform unauthorized actions like data retrieval or privilege escalation.

