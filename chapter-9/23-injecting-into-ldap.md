# Injecting into LDAP

The **Lightweight Directory Access Protocol (LDAP)** is used to query hierarchical directory services over a network. While it typically stores personal and organizational data (e.g., names, emails, phone numbers), LDAP is often integrated into **intranet-facing corporate applications**, such as HR portals.

---

## **LDAP Search Filters**

LDAP queries are constructed using **search filters**, which apply logical operators to locate directory entries matching specific conditions.

### **Common Filter Types**

* **Simple Match**
  * Matches entries based on a single attribute.
  * Example:
    ```ldap
    (username=daf)
    ```

* **Disjunctive Query**
  * Returns entries that match **any** of the listed conditions.
  * Example:
    ```ldap
    (|(cn=searchterm)(sn=searchterm)(ou=searchterm))
    ```

* **Conjunctive Query**
  * Returns entries that satisfy **all** listed conditions.
  * Common in login filters:
    ```ldap
    (&(username=daf)(password=secret))
    ```

---

## **LDAP Injection Overview**

When user input is inserted into search filters without validation or sanitization, attackers can **inject custom filter logic** to manipulate behavior or bypass controls.

### **Potential Outcomes**
* Bypass authentication.
* Retrieve unauthorized data.
* Alter filter structure.

---

## **Challenges in Exploiting LDAP Injection**

Unlike SQL injection, LDAP injection is typically **more constrained and blind**, due to architectural and API-level limitations:

* **Pre-injected Logical Operators**
  * Logical operators like `&` and `|` usually **precede user input** in the query and are **not modifiable**.
  * Limits ability to inject conditions like `or 1=1`.

* **Attributes Are Hard-Coded**
  * Returned attributes are often set in a separate, **non-user-controllable API parameter**.
  * Prevents retrieving arbitrary attributes through injection.

* **Blind Injection by Default**
  * Applications using LDAP often return **minimal or no error messages**.
  * Successful exploitation typically requires **inference-based attacks**.

---

## **Summary**

* LDAP injection exists but is **harder to exploit** than SQL injection.
* Most vulnerabilities occur in filters like:
  ```ldap
  (&(username=[input])(password=[input]))
  ```
* Exploitation usually involves:
  * **Bypassing login logic** via injected filter conditions.
  * **Blind attacks** due to lack of feedback or error detail.

LDAP injection is a **low-noise but real risk**, especially in internal applications where LDAP authentication and directory lookups are prevalent.
