### 🔍 The Functionality

The app allows *any* user (including unauthenticated) to:

* Use a **powerful search feature**.
* See **titles** and **number of matches** for each query.
* But **only subscribers** can open the full documents.

This seems innocent at first, and the design team even believed it could act as *marketing bait*. But it’s actually **leaking way more data than intended**.

---

### 🔒 The Assumption

The devs assumed:

* The search result **titles were too vague** to be useful.
* Users couldn’t extract meaningful content **without reading the full docs** (which is paywalled).

Bad assumption.

---

### 🧠 The Attack: Search Inference

The attack is **search inference** — basically playing 20 questions with the search engine.

Let’s break down how that works **step-by-step**:

---

### 🪄 Step-by-Step Example

#### 📄 Document of Interest:

**Title**: `Press Release 08-03-2011`

But the attacker can’t open it. So instead, they try brute-forcing the content using queries.

---

#### 🧪 Step 1 – Baseline check:

**Query:**

```
wahh consulting
```

**Result:**

```
>> 276 matches
```

Okay — the attacker confirms the topic exists.

---

#### 🧪 Step 2 – Narrow down by title:

**Query:**

```
wahh consulting "Press Release 08-03-2011"
```

**Result:**

```
>> [X] matches (probably 1)
```

Now they isolate **that specific document**.

---

#### 🧪 Step 3 – Binary probing:

Try keywords one at a time to see which ones are in the doc.

**Query:**

```
wahh consulting "Press Release 08-03-2011" merger
```

→ `0 matches`

**Query:**

```
... dividend
```

→ `0 matches`

**Query:**

```
... takeover
```

→ `1 match`

🔥 **Bingo!** “Takeover” is in the document.

---

#### 🧪 Step 4 – Drill deeper:

Now try company names:

```
... takeover haxors inc → 0
... takeover ngs        → 1 ✅
... takeover ngs cancelled → 0
... takeover ngs completed → 1 ✅
```

➡️ Even though they **never saw the document**, they now know:

> *“Wahh Consulting took over NGS, and the takeover was completed.”*

Purely through **match count side-channels**.

---

### 💣 Real-World Parallel

This is the same technique used in:

* **Blind SQL injection** (use responses/errors to infer database content)
* **Timing attacks** on login or cryptographic APIs
* **Blind XSS payload discovery** via reflected parameters

Also: The authors even used this on an **internal wiki** to brute-force passwords stored in pages using queries like:

```
Password=A
Password=B
Password=BA
...
```

Since the search engine matched **substrings**, it revealed valid character progressions — **like hot/cold guessing**.

---

### 🚨 Core Issue

This is a **logic flaw**, not a traditional vulnerability. The app works “correctly” — it just makes bad assumptions:

* Assuming showing **match count** is harmless.
* Assuming **titles aren’t revealing**.
* Assuming **no one will brute-force queries**.

---

### 🛠️ HACK STEPS (What You’d Do)

1. **Send generic keyword queries** and note the match count.
2. **Add more words** iteratively and watch how the result set changes.
3. **Automate** this if needed (with Python, Burp macros, etc.) to probe documents at scale.
4. **Target known title patterns** like “2024 Security Audit,” “Product Launch,” “Password Reset,” etc.

---

### ✅ Defense Tips

* Limit result details for unauthenticated users.
* Don’t show **match counts** for protected content.
* Enforce rate-limiting to prevent brute-force-style search abuse.
* Consider **tokenized search** (only allow known, whitelisted terms).
* Sanitize sensitive titles or disable search on protected content altogether.

---
