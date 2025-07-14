# Blind XPath Injection

**Blind XPath Injection** extends the informed variant by removing the need to know any part of the XML structure in advance — not even the names of elements or attributes. This approach uses **relative navigation** and **XPath functions** to enumerate and extract data from an XML document entirely through inference.

---

## **Relative Path Exploitation**

XPath supports **relative queries**, allowing attackers to:

* Navigate **up or down** the XML hierarchy using axes like `parent::*`, `child::*`, etc.
* Query **meta-information**, such as element names, via the `name()` function.

This means an attacker can:
* Identify element names.
* Determine structure depth.
* Retrieve data — all without knowing the XML schema.

---

## **Example: Discovering Node Names**

To extract the name of the current node’s parent:

```xpath
' or substring(name(parent::*[position()=1]),1,1)= 'a
```

If the parent node's name starts with `'a'`, this query will succeed. To discover the **second character**, supply:

```text
' or substring(name(parent::*[position()=1]),2,1)= 'a
' or substring(name(parent::*[position()=1]),2,1)= 'b
' or substring(name(parent::*[position()=1]),2,1)= 'c
' or substring(name(parent::*[position()=1]),2,1)= 'd  <-- True (if parent is "address")
```

By repeating this, attackers can discover:
* **Full element names**
* **Hierarchy relationships**

---

## **Example: Extracting Node Values by Position**

Instead of targeting by name, nodes can be referenced **by index**:

* Retrieve `Hunter` (3rd `<address>`, 4th child node):
```xpath
//address[position()=3]/child::node()[position()=4]/text()
```

* Retrieve `letmein` (3rd `<address>`, 6th child node):
```xpath
//address[position()=3]/child::node()[position()=6]/text()
```

This allows enumeration of all XML values using positional access.

---

## **Fully Blind Attack via Condition-Based Inference**

If the application doesn’t directly return results, inference can still be applied:

```text
' or substring(//address[position()=1]/child::node()[position()=6]/text(),1,1)= 'M' and 'a'='a
```

This query checks if the **first character** of the **6th child node** in the **first address** is `'M'`.

Repeat for:
* Different positions of `substring()`
* Different child node indexes
* Different `<address>` node indexes

---

## **TIP: Useful XPath Functions for Automation**

To automate node traversal and value extraction:

* `count(node-set)`
  - Returns the **number of child nodes**.
  - Helps determine how many `position()` values to iterate.

* `string-length(string)`
  - Returns the **length of a node’s value**.
  - Useful for limiting how many characters to extract via `substring()`.

---

## **Summary**

* Blind XPath injection can reveal the **entire structure and content** of an XML document.
* No prior knowledge of the XML schema is required.
* Exploitation is driven by:
  - **Relative XPath navigation**
  - **Position-based node targeting**
  - **Conditional logic with substring(), name(), and other XPath functions**
