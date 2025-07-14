# Defects in Multistage Login Mechanisms

Some applications implement **multistage login mechanisms** to enhance security by requiring multiple credentials or actions across several steps. Common stages include:

- Username and password submission  
- Entry of specific digits from a PIN or memorable word  
- Use of a one-time token or value from a physical device  

While multistage login seems more secure on the surface, it is often **more prone to logic flaws** and implementation errors. In some cases, it can even be **less secure** than simple username/password login.

---

## Common Design Flaws

### Assumption of Sequential Integrity

- The application assumes that completing stage three implies prior success at stages one and two.  
- An attacker may bypass stages by jumping directly to later ones (e.g., POSTing directly to stage three's URL).  

**Example:**  
```
POST /login-step3 HTTP/1.1  
Host: app.example.com  
Cookie: sessionid=abc123  
Content-Type: application/x-www-form-urlencoded  

token=123456  
```

### Trusting Prior Validated Data

- Data validated in stage one is trusted in stage two without rechecking.  
- Example: A flag like `isAdmin=true` validated early is later accepted without verification.  
- Attackers can tamper with these values during stage transitions.  

**Example:**  
```html
<input type="hidden" name="role" value="admin" />
```

### Inconsistent Identity Across Stages

- The application may not verify that the same user identity is used throughout the login process.  
- An attacker can submit valid credentials for two different users across two stages.  
- This enables **partial credential possession attacks** — such as:
  - Using user A’s password in stage one  
  - Submitting user B’s token in stage two  
  - Getting authenticated as either A or B

> 🔒 **Common Myth:** Multistage mechanisms are inherently secure.  
> ❌ **Reality:** They are **more complex** and therefore more vulnerable to implementation bugs and logic flaws.

---

## Common Design Flaws in Random Challenges

Some login mechanisms attempt to enhance security by introducing **randomly varying questions** at a certain stage of the login process. For example:

- A random “secret question” (mother’s maiden name, first school, etc.)  
- A prompt for two specific letters from a user-defined phrase  

The **goal** of this behavior is to prevent replay attacks. If an attacker captures the user’s input during one session, they shouldn’t be able to reuse it, since a **different question** will be asked next time.

However, these implementations are frequently flawed.

### Client-Controlled Challenge Storage

- The randomly selected question is stored **client-side**, often in:
  - A hidden HTML form field  
  - A cookie  
- The user submits **both the question and the answer**, allowing an attacker to:
  - Change the question  
  - Submit an answer they know  
  - Bypass the randomized challenge  

**Example:**  
```html
<input type="hidden" name="question" value="What is your pet's name?" />
<input type="text" name="answer" value="Fluffy" />
```

### Stateless Question Rotation

- A new random question is generated **every time** the login is retried.  
- The application **does not track** which question was shown to a specific user during a failed login.  
- An attacker can:
  - Retry the login process repeatedly  
  - Wait for a question they know the answer to  
  - Complete the login successfully  

> ⚠️ **NOTE:** This flaw is subtle and easy to overlook. Many real-world apps using "two random letters from a memorable word" fall into this trap. An attacker can wait for their known letters to be prompted, **without triggering account lockout**.

---

## Composite Login Form Vulnerability

- Some applications present **username, password, and a secret question** all on the same login page.  
- The secret question changes on each page load.  
- An attacker capturing this form submission can simply:
  - Replay the entire request, including the known secret question  
  - Completely **bypass the randomized protection**  

**Example:**  
```
POST /login HTTP/1.1  
Host: app.example.com  
Content-Type: application/x-www-form-urlencoded  

username=alice&password=pass123&question=Your%20school&answer=Lincoln
```

### Persistent Cookie for Question Binding

- Some apps attempt to bind the user to a specific random question via a **persistent cookie**.  
- This is easily bypassed by:
  - Deleting the cookie  
  - Modifying the cookie value  
  - Restarting the session  

**Example:**  
```
Cookie: questionID=5  
```

---

## HACK STEPS

1. **Baseline Walkthrough**
   - Perform a full login using a valid account.  
   - Record all requests and responses using an intercepting proxy (e.g., Burp Suite).

2. **Map Each Stage**
   - Identify distinct login stages and what data is collected at each.  
   - Watch for:
     - Duplicate submissions (e.g., username appears at stage 1 and 2)  
     - Values in hidden fields, cookies, or URL parameters  

3. **Stage Tampering Tests**
   - Try login steps **out of order**  
   - Attempt to **skip** stages  
   - Jump directly to stage 2 or 3 without completing earlier stages  
   - Look for unanticipated entry points into each stage

4. **Cross-Stage Credential Substitution**
   - Submit mismatched values across stages:  
     - Example: Username/password of user A at stage one  
     - Username/token of user B at stage two  
   - Test whether login still succeeds

5. **State Manipulation**
   - Look for indicators of login progress stored in client-side data:
     - Hidden form fields (e.g., `stage2complete=true`)  
     - Cookies or URL parameters  
   - Modify these to force transitions or skip steps

6. **Check for Client-Controlled Question**

   - If the random question is included in a form field or cookie, try:
     - Changing the question  
     - Submitting the corresponding known answer  
     - Verifying if login still succeeds

7. **Probe for Stateless Behavior**

   - Perform multiple partial logins with the same account  
   - Record the question shown each time  
   - If it changes, the attacker can **cycle through questions** until a known one appears  

8. **Replay Composite Forms**

   - If all credentials (username, password, secret question) are submitted together:
     - Replay the captured request with the same values  
     - Check whether login still works

9. **Test Cookie-Based Question Binding**

   - If a persistent cookie is used to keep the same question:
     - Delete or edit the cookie  
     - Reload the login page to get a different question

---

## TIP

Multistage login often uses **client-submitted data** to track progress. If that data is not properly **validated** or **signed**, it can be modified to:

- Skip authentication stages  
- Override account status flags  
- Confuse identity validation logic  

Always inspect how the application **stores and reuses** login-related state between requests.

> **Defensive Tip:** Store login state and challenge questions server-side, tied to session tokens. Never rely on hidden form fields or cookies for trust-critical data.

---

## Summary Table

| Flaw Type                     | Description                                                                 | Risk Level         | Exploitable For                          |
|------------------------------|-----------------------------------------------------------------------------|--------------------|------------------------------------------|
| Stage skipping                | Later login stages do not verify completion of earlier ones                | High               | Login bypass                             |
| Trusting prior validation     | Data validated at stage one is trusted at stage two                        | High               | Privilege escalation                     |
| Cross-user credential mixing  | Different credentials across stages are not properly matched               | High               | Authentication as another user           |
| Client-controlled state flags | Login progress tracked via editable form fields or cookies                 | Medium–High        | Stage bypass, session abuse              |
| Client-side question storage  | Attacker can choose question to answer                                     | High               | Bypass of challenge question              |
| Stateless question rotation   | New random question on every attempt without tracking                      | High               | Replay with known answer                  |
| Composite form replay         | Full credential set captured and replayed                                  | Medium–High        | Defeats the purpose of random challenge   |
| Cookie-bound challenge        | Challenge tied to a modifiable cookie                                      | Medium             | Easy bypass via cookie manipulation       |
