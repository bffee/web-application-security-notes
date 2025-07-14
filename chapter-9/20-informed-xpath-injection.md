# Informed XPath Injection

**Informed XPath Injection** uses **conditional logic** to infer data from XML documents by exploiting application responses to crafted XPath queries — much like **blind SQL injection**.

This method is useful when:
* The application does **not display** query results directly.
* You can observe a **behavioral difference** (e.g., login success/failure) based on query outcomes.

---

## **Boolean-Based Condition Testing**

Two different password inputs can reveal whether a certain condition is true:

```text
' or 1=1 and 'a'='a      --> TRUE → Response returned
' or 1=2 and 'a'='a      --> FALSE → No results
```

* The **difference in responses** allows attackers to **confirm conditions** in the underlying XPath query.

---

## **Character-by-Character Extraction**

Like SQL, XPath supports **string functions** such as `substring()`, which attackers can use to retrieve data one character at a time.

### **Example Attack: Extract First Character of Password**
Suppose you want to extract the first character of Gates' password:

```text
' or //address[surname/text()='Gates' and substring(password/text(),1,1)='M'] and 'a'='a
```

The resulting XPath query becomes:
```xpath
//address[surname/text()='Dawes' and password/text()=''
// OR
//address[surname/text()='Gates' and substring(password/text(),1,1)='M']
// AND 'a'='a']/ccard/text()
```

* If the first character is `'M'`, a response is returned.
* Otherwise, the query fails silently.

### **Full Password Extraction**
By repeating this method:
* Vary the `substring(password/text(), N, 1)` for each position.
* Cycle through possible characters (e.g., A–Z, a–z, 0–9).
* Reconstruct the full password **one byte at a time**.

---

## **Key Takeaways**

* Informed XPath injection works **without direct output**, relying on **response-based inference**.
* Requires:
  - Ability to inject XPath syntax.
  - Application behavior that changes based on query results.
* Similar in principle to **blind/inference SQL injection**.
* Enables **precise data extraction**, especially credential fields.

---
