# Injecting into XPath

**XPath (XML Path Language)** is an interpreted language used for navigating and extracting data from **XML documents**. When applications use user input to construct XPath queries without proper sanitization, they may become vulnerable to **XPath injection** — a flaw similar in concept to SQL injection.

---

## **Common Use Cases**

* XPath is often used to retrieve data from **XML-based storage**.
* XML documents may store:
  - **Application configuration**
  - **User credentials and roles** (especially in smaller applications)
* Queries are often built dynamically based on user input.

---

## **Sample XML Document**
```xml
<addressBook>
  <address>
    <firstName>William</firstName>
    <surname>Gates</surname>
    <password>MSRocks!</password>
    <email>billyg@microsoft.com</email>
    <ccard>5130 8190 3282 3515</ccard>
  </address>
  <address>
    <firstName>Chris</firstName>
    <surname>Dawes</surname>
    <password>secret</password>
    <email>cdawes@craftnet.de</email>
    <ccard>3981 2491 3242 3121</ccard>
  </address>
  <address>
    <firstName>James</firstName>
    <surname>Hunter</surname>
    <password>letmein</password>
    <email>james.hunter@pookmail.com</email>
    <ccard>8113 5320 8014 3313</ccard>
  </address>
</addressBook>
```

---

## **XPath Query Examples**

* **Retrieve all email addresses:**
```xpath
//address/email/text()
```

* **Retrieve all details for user with surname 'Dawes':**
```xpath
//address[surname/text()='Dawes']
```

---

## **Injection Scenario: Credential Validation**

Imagine the app authenticates users and retrieves credit card data via this XPath:
```xpath
//address[surname/text()='Dawes' and password/text()='secret']/ccard/text()
```

An attacker could bypass authentication by submitting the following password:
```text
' or 'a'='a
```

The resulting XPath becomes:
```xpath
//address[surname/text()='Dawes' and password/text()='' or 'a'='a']/ccard/text()
```

* The injected logic **bypasses** the actual password check.
* **All matching records** are returned — equivalent to a SQL injection attack.

---

## **Important Notes**

* **Single quotes** are required when injecting into string fields but **not** for numeric fields — same as SQL.
* **XPath keywords and XML element names are case-sensitive.**
  - This differs from SQL, where case sensitivity is typically less strict.

---

## **Key Takeaways**

* XPath injection is **functionally identical** to SQL injection but targets XML data stores.
* Applications embedding user input into XPath expressions must sanitize and validate that input properly.
* As with all injection flaws, parameterization or context-aware escaping should be applied to prevent exploitation.

---
