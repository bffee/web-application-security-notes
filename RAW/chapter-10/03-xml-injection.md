# 🧨 Injecting into XML Interpreters (XXE)

Welcome to one of the nastier corners of web app security: **XML External Entity (XXE) attacks**. These bugs are like **path traversal + SSRF + DoS + LFI** rolled into one juicy vulnerability — especially when applications mishandle XML.

## 📦 Why XML?

XML is used everywhere:

* Web apps (in AJAX, SOAP, etc.)
* Backend API communication
* File uploads (like `.xml` configs)
* SAML (Single Sign-On)
* Mobile apps using REST/SOAP

Apps parse XML to extract and process data — and this parsing step is where it all goes sideways.

---

## 🕵️‍♂️ What Is XXE?

When an XML parser accepts **user input** and allows entity definitions, it opens the door for **XML External Entities** — specially crafted placeholders that can:

* Pull **internal files**
* Trigger **SSRF**
* Perform **port scanning**
* Cause **denial-of-service**
* Sometimes even **RCE**

---

## 🧬 Let's Break It Down

### ✅ Legit XML Example:

```xml
<Search><SearchTerm>nothing will change</SearchTerm></Search>
```

This is what a normal user would send. The app just echoes back the result like:

```xml
<Search><SearchResult>No results found for expression: nothing will change</SearchResult></Search>
```

Now what if the server-side XML parser is misconfigured and **accepts a custom DOCTYPE**? You can define your own entities. 😈

---

## 💀 Malicious DOCTYPE: Define External Entity

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///windows/win.ini"> ]>
<Search><SearchTerm>&xxe;</SearchTerm></Search>
```

### What’s Happening:

* You define an entity `xxe` that pulls the local file `/windows/win.ini`.
* You place that entity `&xxe;` where input is reflected back.
* If the parser is vulnerable, it fetches and returns file contents in the response.

---

## 💣 Example: XXE in Action

### Request:

```
POST /search/128/AjaxSearch.ashx HTTP/1.1
Content-Type: text/xml

<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///windows/win.ini"> ]>
<Search><SearchTerm>&xxe;</SearchTerm></Search>
```

### Response:

```xml
<Search>
  <SearchResult>No results found for expression: ; for 16-bit app support
  [fonts]
  [extensions]
  ...
</SearchResult></Search>
```

Boom. You just read files on the server.

---

## 🌐 XXE Over HTTP – SSRF via XML

It’s not just local files. You can define entities to pull content over the network.

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://192.168.1.1:25"> ]>
<Search><SearchTerm>&xxe;</SearchTerm></Search>
```

### Now You Can:

* **Bypass firewalls** using the app as a proxy
* **Scan internal ports** via timing or banner responses
* **Exploit internal services** like Redis, Elasticsearch, Gogs, Jenkins

---

## 🧪 XXE Attack Use Cases

| Attack Type       | Example                                                       |
| ----------------- | ------------------------------------------------------------- |
| 🕵️ LFI           | `file:///etc/passwd`, `file:///windows/win.ini`               |
| 🔥 SSRF           | `http://internal-api:8080/admin`                              |
| 🛠️ Port Scanning | Loop through `192.168.0.1:22`, `:80`, `:3306`                 |
| 💥 DoS            | `file:///dev/random` or recursive entities                    |
| 🐚 RCE            | Rare, but possible via deserialization tricks in some parsers |

---

## 🧨 Bonus: Denial of Service

### Classic DoS Payload:

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///dev/random"> ]>
<Search><SearchTerm>&xxe;</SearchTerm></Search>
```

This causes the parser to **hang indefinitely**, reading an endless stream of entropy from `/dev/random`. Result: **server crash** or **high CPU usage**.

---

## 🧠 Why This Is Dangerous

* Many XML parsers enable **entity expansion** by default.
* Devs often trust XML input, especially in internal services.
* It’s easy to miss during development but deadly in production.

---

## 🛡️ Defense 101

We’ll go deeper into prevention in a later section, but just so you're aware:

* Disable external entities in all XML parsers.
* Use safe libraries with secure defaults (e.g., `defusedxml`, `.NET XmlReaderSettings`, etc.).
* Validate schema — never accept arbitrary XML without validation.

---

### ✅ Try It Yourself

Wanna test your skills?

* Load up Burp Suite or Postman
* Find an app that accepts XML
* Inject your own `<!DOCTYPE>` with an entity
* Reflect a local file, or see if it triggers network connections (monitor with `tcpdump`)

---

## ❓5 Quality Questions (Not Quantity)

1. **Why is `file:///windows/win.ini` used in XXE testing on Windows servers?**
2. **What’s the purpose of the DOCTYPE tag in an XML document when exploiting XXE?**
3. **What protocols can you use inside an external entity definition? Name at least two.**
4. **How can an XXE attack help an attacker perform internal port scanning?**
5. **What would happen if you defined an entity like `<!ENTITY xxe SYSTEM "file:///dev/random">` in your XML?**

---

## 🧼 Injecting into SOAP Services – Full Breakdown

SOAP (Simple Object Access Protocol) is like the **old-school API courier** — it’s XML-based and often used in **backend communications** between services in large enterprise setups.

You probably won’t see it in modern frontend-to-backend APIs (JSON is king now), but it’s **still common behind the curtain**, especially in **banking**, **enterprise web apps**, and **legacy systems**.

---

### 🧪 What is SOAP?

* Protocol for transferring **structured data** via XML.
* Used to **connect backend components**, even if they’re on **different systems or platforms**.
* Common in **service-oriented architecture (SOA)**.

#### Example:

When a user submits a form to transfer funds, SOAP might be used **behind the scenes** like this:

**HTTP Request from Browser (Frontend):**

```
POST /bank/Default.aspx
FromAccount=18281008&Amount=1430&ToAccount=08447656
```

**SOAP Message Between Backend Components:**

```xml
<soap:Envelope>
  <soap:Body>
    <pre:Add>
      <Account>
        <FromAccount>18281008</FromAccount>
        <Amount>1430</Amount>
        <ClearedFunds>False</ClearedFunds>
        <ToAccount>08447656</ToAccount>
      </Account>
    </pre:Add>
  </soap:Body>
</soap:Envelope>
```

---

## 🎯 Goal of SOAP Injection

Manipulate the backend SOAP message to:

* **Bypass logic checks** (like ClearedFunds=False)
* **Insert fake values**
* **Comment out logic**
* **Trigger unauthorized behavior**

---

## 🚨 SOAP Injection Attack Examples

### ⚔️ **1. Classic Injection**

Inject custom tags (like another `<ClearedFunds>True</ClearedFunds>`) **before** the legit one:

```http
FromAccount=18281008&
Amount=1430</Amount><ClearedFunds>True</ClearedFunds><Amount>1430&
ToAccount=08447656
```

🔍 If the backend reads **only the first `<ClearedFunds>`**, the attacker **forces approval**, even with no money.

---

### ⚔️ **2. Tag Injection + Comment**

Inject tag and comment out rest of the XML to break logic:

```http
Amount=1430</Amount><ClearedFunds>True</ClearedFunds>
<ToAccount><!--
```

And then:

```http
ToAccount=08447656-->&Submit=Submit
```

👉 You’re using XML comments to **remove** legit parts of the original message and **insert your own logic**.

---

### ⚔️ **3. Full SOAP Injection**

Try to **override the full SOAP structure** from inside a parameter.

```xml
<ToAccount>08447656</ToAccount></Account></pre:Add></soap:Body></soap:Envelope>
<!--&Submit=Submit
```

🚫 ⚠️ This is **risky and often fails**, unless the app uses **custom XML parsers** that are **weak or homegrown**.

---

## 🕵️‍♂️ Finding SOAP Injection – HACK STEPS

### ✅ 1. **Insert Broken XML Tag**

Try something like:

```html
</foo>
```

If you get an **XML error**, your input is probably being **parsed into a SOAP message**.

---

### ✅ 2. **Insert Proper XML Tags**

Try:

```html
<foo></foo>
```

If error disappears, you may have **SOAP injection**.

---

### ✅ 3. **Check Response Normalization**

Try submitting:

* `test<foo/>`
* `test<foo></foo>`

If the app changes these, it’s parsing them — you’ve likely got **injection opportunity**.

---

### ✅ 4. **Cross-Parameter Comment Injection**

Inject `<!--` in one parameter and `-->` in another:

```http
FromAccount=<!--
ToAccount=08447656-->
```

💣 If it changes app logic or causes weird output — you’ve just **commented out** part of the SOAP structure.

---

### ⚠️ Real-World Difficulty:

* Without **verbose errors**, exploitation is hard.
* **Guessing structure** = near impossible unless lucky.
* Error messages that show XML structure are **goldmines**.

---

## 🛡️ Preventing SOAP Injection

To defend against it:

### 🔐 Input Filtering (Boundary Validation)

* Validate all incoming input.
* Check both **current request data** and **previously stored data**.

### 🔒 HTML Encode Metacharacters

Convert:

* `<` to `&lt;`
* `>` to `&gt;`
* `/` to `&#47;`

💡 This stops user input from **breaking the XML structure** — the app treats it as plain data.

---

## 🧠 Realistic Threats

* Modify bank transfers
* Tamper user roles
* Force logic to accept invalid inputs
* Break out of logic & hijack SOAP requests
* Full backend manipulation in misconfigured SOAP systems

---

### 🧪 Try It Live (Demo Targets from the Book):

* Good error feedback: [http://mdsec.net/bank/27/](http://mdsec.net/bank/27/)
* Minimal error feedback:
  [http://mdsec.net/bank/18/](http://mdsec.net/bank/18/)
  [http://mdsec.net/bank/6/](http://mdsec.net/bank/6/)

---

## 🧩 Next: Knowledge Check (Only 5 questions, promise)

Here’s your turn to test your understanding:
**Try to answer without scrolling up — trust your brain.**
If you get stuck, no worries — I’ll explain every bit.

---

### 🔍 SOAP Injection Practice Questions

1. **What’s the purpose of injecting a duplicate `<ClearedFunds>` tag in a SOAP message?**
2. **What are XML comments (`<!-- -->`) used for in a SOAP injection attack?**
3. **Why does injecting raw `<` or `</foo>` sometimes cause errors in SOAP-based apps?**
4. **How does encoding `<`, `>`, and `/` help in preventing SOAP injection?**
5. **Why are custom or homegrown XML parsers more vulnerable to full-structure injection attacks?**

---
