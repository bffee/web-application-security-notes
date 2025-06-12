# 🧭 Mapping the Application – Application Pages vs Functional Paths

## 📌 Core Concept

Traditional URL-based mapping assumes each web page/function corresponds to a unique URL path. But **modern applications** (e.g., using Java servlets, frameworks, REST) may route all requests to a single endpoint, using **parameters to define functions**.

---

## 🔸 Two Conceptual Models

### 1. **Application Pages Model (Traditional)**

* Web content is structured like files in directories.
* Example: `/admin/editUser.jsp`
* Each page/function maps to a unique URL.
* Suitable for classic/static or simple dynamic websites.
* Crawlers/spiders can easily map the site.

### 2. **Functional Paths Model (Modern Applications)**

* All requests go to a central script (e.g., `/bank.jsp`).
* Function is determined by parameters:

  ```http
  POST /bank.jsp
  servlet=TransferFunds&method=confirmTransfer&...`
  ```
* Parameters like `servlet` and `method` define the logic.
* Example Functional Paths Map:

  * `TransferFunds.selectAccounts`
  * `TransferFunds.confirmTransfer`
  * `BillPayment.addPayee`
  * `WahhBank.logout`
* URL mapping fails to uncover real app logic.

---

## ✨ Advantages of Functional Paths Mapping

* Captures actual **application logic**, not just URL paths.
* Useful for understanding **logic flow** and **developer assumptions**.
* Helps in formulating logic-based attacks.
* Reveals internal structure even when URLs are not unique.

---

## 🚀 HACK STEPS

### Step 1: Identify Parameter-Based Function Calls

* Look for requests like:

  * `/admin.jsp?action=editUser`
  * `/app?module=users&op=delete`
* These indicate function is passed via a parameter.

### Step 2: Modify Discovery Techniques for Functional Parameters

* Analyze behavior for:

  * Invalid function/method names
  * Valid function with invalid params
* Look for patterns in HTTP responses:

  * Status codes
  * Error messages
  * Response size/timing
* Enumerate:

  * **Servlets/modules** (e.g., `TransferFunds`, `BillPayment`)
  * **Methods/actions** (e.g., `confirmTransfer`, `selectPayee`)
* Use **wordlists** and **inference** to discover hidden functions.

### Step 3: Build a Functional Path Map

* Catalog each discovered function.
* Note logical relationships (e.g., `login ➞ home ➞ transfer`).
* Helps understand business logic & potential attack vectors.

---

## 🔒 Practical Tip

> For apps using this model, traditional URL crawling and brute-forcing may **miss all hidden logic**. You must adapt enumeration tools and methods to probe functional parameters effectively.

---

## 🔍 Summary

| Model             | Mapping Focus      | Detection Method                  | When to Use            |
| ----------------- | ------------------ | --------------------------------- | ---------------------- |
| Application Pages | URL structure      | Spidering / URL brute force       | Static or classic apps |
| Functional Paths  | Parameters & logic | Parameter fuzzing & logic mapping | Modern dynamic apps    |

Understanding the **real structure** of the app helps craft **better attacks** and reveals **hidden functions** traditional tools miss.
