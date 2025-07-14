# Forgotten Password Functionality

Forgotten password mechanisms are often implemented insecurely and become the weakest link in the authentication system. While they aim to help users regain access, they frequently reintroduce vulnerabilities such as username enumeration, brute-force attacks, and insecure password resets.

---

## Common Design Weaknesses

### 1. Secondary Challenge-Based Authentication
- Users are prompted with secondary questions like:
  - Mother’s maiden name
  - Memorable dates
  - Favorite color
- These answers:
  - Have a smaller range of possible values than typical passwords
  - Are often publicly known or easily discoverable
- Many applications allow users to choose their own questions and answers during registration, often selecting trivially guessable ones like:
  - *Do I own a boat?*

### 2. Brute-Forceable Challenge Answers
- Password recovery challenges often don’t implement brute-force protection.
- Even if brute-force is blocked on the main login, it may not be implemented here.
- This makes it easy for attackers to:
  - Use automated scripts
  - Iterate through challenge responses
  - Compromise accounts

### 3. Password Hints
- Instead of challenges, some apps use hints defined by users.
- Users often:
  - Set vague or highly guessable hints
  - Repeat their password as the hint
- An attacker with enumerated usernames can harvest hints and perform targeted guessing.

### 4. Weak Recovery Logic
The logic for password recovery is frequently flawed:

#### Secure Approach
- Unique, unguessable, time-limited recovery URL sent to the user’s registered email.

#### Insecure Implementations
- **Password Disclosure**: The app displays the actual password after the challenge.
- **Automatic Login**: The app logs the user in immediately after the challenge without password change or notification.
- **User-specified Email Delivery**: Reset URL is sent to an attacker-supplied email address.
- **No Notification**: No email is sent after reset, allowing attackers to maintain silent access.

---

## HACK STEPS

1. **Identify the forgotten password function**  
   - Even if not linked from the UI, check for it manually (use discovery techniques from Chapter 4).
  
2. **Walk through the function with a known account**  
   - Understand the flow, logic, and all input points.

3. **Challenge harvesting**  
   - If user-defined challenges are used:
     - Use a list of common/enumerated usernames
     - Harvest all challenge questions
     - Prioritize weak or guessable ones for attack

4. **Hint harvesting**  
   - If hints are used:
     - Collect them via usernames
     - Attempt guessing based on obvious or reused hints

5. **Check for brute-force potential**  
   - Attempt multiple responses to recovery challenges
   - Verify whether rate limiting, CAPTCHA, or account lockout exists

6. **Analyze recovery URLs**  
   - If emails are used to send reset links:
     - Capture multiple URLs
     - Look for patterns or predictability
     - Apply token analysis methods from Chapter 7

7. **Inspect for email tampering**  
   - Even if the email field isn’t visible, it may:
     - Be passed in a hidden field
     - Be embedded in a cookie
   - Modify the email and monitor for reset links to attacker-controlled inboxes

---

## TIP

Even when no visible email field is presented, always inspect the form or intercepted request. Hidden fields or cookies may:
- Leak a user’s email address (information disclosure)
- Allow attackers to override the destination and hijack the reset flow

If such override is possible:
- It creates a complete bypass of the authentication system
- You can compromise accounts without even solving the challenge

Also, if the application allows a reset and does not notify the user, it enables stealth compromise:
- The user may not realize what happened
- The attacker can rotate through victims without raising alarms

---

## Summary Table

| Weakness Type                         | Description                                                                 |
|--------------------------------------|-----------------------------------------------------------------------------|
| Easy-to-guess challenges             | Small answer space, publicly known data                                    |
| Brute-forceable answers              | No rate-limiting, CAPTCHA, or lockout                                       |
| Weak password hints                  | User sets obvious or reused hints                                           |
| Password disclosure                  | App shows the forgotten password                                            |
| Automatic login                      | App logs in attacker after answering the challenge                          |
| Attacker-defined recovery email      | App sends reset URL to an email provided by attacker                        |
| No reset notification                | Account owner unaware of compromise                                         |
| Hidden email override                | Email destination may be set via hidden fields or cookies                   |
