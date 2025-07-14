# Retrieving Data as Numbers

When **string-based SQL injection** is blocked due to proper handling of quotes, vulnerabilities may still exist in **numeric data fields**. In such cases, injection is possible only if the application **directly reflects numeric results** from SQL queries.

---

## **Numeric-Based Data Extraction**

Even without a visible string output, **character data can be extracted as numbers** using SQL functions.

### **Core Functions**

- `ASCII(char)` – Returns the ASCII value of a character.
- `SUBSTRING(str, pos, len)` / `SUBSTR(str, pos, len)` – Returns part of a string.

### **Example:**
Extract and convert the first character of `'Admin'` to its ASCII code:

```sql
ASCII(SUBSTRING('Admin',1,1)) → 65
```

### **Process:**
- Use injection to call `ASCII(SUBSTRING(...))` on a secret value.
- The response reflects a number (e.g., `65`).
- Convert it back to a character (`A`).
- Repeat for each position to reconstruct the full string.

---

## **Automated Character-by-Character Extraction**

This method allows:
- **Blind extraction**: one character at a time.
- **Scripted automation** for large datasets.
- Works even when **error-based** or **visible UNION** injections fail.

---

## **Special Case: Identifier-Based Retrieval**

- Sometimes, the application doesn’t return numeric values directly.
- Instead, it returns a **resource** (e.g., a document) linked to a numeric ID.
  
### **Strategy:**
1. Crawl the application to create a **map of document ID → document contents**.
2. Inject numeric-based payloads that cause the app to return specific documents.
3. Use the response to **infer the numeric value** (i.e., which character it represents).

---

## **TIP**

*Use ASCII and SUBSTRING to extract string values numerically when direct output isn’t possible. Combine these in blind SQLi for effective inference. The mapping approach is useful when IDs are indirectly tied to content.*

- For detailed behavior across databases: [sqlzoo.net string handling differences](http://sqlzoo.net/howto/source/z.dir/i08fun.xml)

---
