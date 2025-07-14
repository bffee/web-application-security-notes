# Finding LDAP Injection Flaws

LDAP injection is harder to detect than SQL injection, primarily due to the **lack of informative error messages**. In most cases, you must rely on:

* **Search result variations**.
* **Generic server errors** (e.g., HTTP 500).
* **Heuristic indicators** based on crafted inputs.

Despite these limitations, several effective techniques can help identify LDAP injection vulnerabilities.

---

## **HACK STEPS**

### **Step 1: Submit Wildcard Input**

```text
*
```

* The asterisk `*` acts as a **wildcard in LDAP**, but not in SQL.
* If a **large number of results** are returned, it strongly suggests the input is evaluated in an LDAP context.
* This behavior **does not occur** with SQL databases, making it a useful fingerprinting technique.

---

### **Step 2: Submit Excess Closing Brackets**

```text
))))))))))
```

* This input attempts to **close any open brackets** from the injected input and the original LDAP filter.
* If the application **throws an error** (especially a server error), this may indicate:
  * LDAP injection vulnerability.
  * Broken query construction due to input injection.

> 🔎 This is **not a definitive sign on its own**, as malformed input can break various application features. Use only when you suspect LDAP usage.

---

### **Step 3: Inject LDAP-Specific Filters**

These are general-purpose payloads that attempt to **modify or extend the LDAP filter** structure. Use these even when you lack schema details:

```text
)(cn=*
*))(|(cn=*
*))%00
```

* `cn` (common name) is a **universally supported** LDAP attribute.
* These inputs:
  * Attempt to **close the original filter**.
  * Inject new filters (e.g., wildcard matches on common attributes).
  * Include `%00` to test for **NULL byte truncation** (used to comment out trailing filter logic).

> ✅ If the application returns **more results than expected**, or any **behavioral change** occurs without error, the input is likely being interpreted within an LDAP filter.

---

## **Key Indicators of Vulnerability**

* **Unusual results** from minimal or malformed inputs.
* **Large response sets** from wildcard searches.
* **Unmatched bracket errors** when over-closing filters.
* **Server errors (500)** when injecting malformed filters.

---

## **Next Steps**

If you identify signs of LDAP injection:
* Attempt **filter structure manipulation** (e.g., batching filters, null truncation).
* Try injecting **known attributes** like `cn`, `uid`, or `mail`.
* Determine whether **access control logic** can be bypassed by injecting wildcard or filter-breaking logic.

---

Let me know when you're ready for the next section.
