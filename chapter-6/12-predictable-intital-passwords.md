# Predictable Initial Passwords

Some applications — especially **intranet-based corporate systems** — create user accounts in **bulk** and assign **initial passwords** that follow a **predictable format**. These passwords are often delivered through printed notices, internal emails, or verbal communication.

If the password generation logic is weak or deterministic, an attacker may **predict the initial passwords** for other users and gain unauthorized access.

---

## Why This Is a Problem

### 1. Uniform or Correlated Passwords
- Some systems assign the **same default password** to every new user.
- Others use **user-specific but predictable logic**, like:
  - First name + birth year → `jane1988`
  - Job title + number → `admin123`
  - Username as the password → `jdoe → jdoe`

### 2. Small Sample = High Accuracy
- Even with a **very small sample set** (e.g. 3–5 accounts), attackers may:
  - Spot recurring structures or patterns.
  - Predict other users’ passwords with high accuracy.

### 3. Brute-Force Friendly
- Even when exact prediction isn't possible, **partially derived passwords** can be used to build an **effective wordlist**.
- This can reduce the time and effort needed for a **brute-force** or **credential stuffing** attack.

---

## HACK STEPS

1. **Identify auto-generated passwords**:
   - Create or capture several test accounts in quick succession.
   - Examine whether the passwords follow a **recognizable pattern**.

2. **Look for correlations**:
   - Between the **username/job title/email** and the password.
   - Between **multiple captured passwords**.

3. **Extrapolate** the pattern:
   - Build a list of **likely passwords** for other users.
   - If a direct correlation exists, try **logging in** with guessed usernames and predicted passwords.

4. **Fallback brute-force**:
   - Use your generated password list in combination with a list of **enumerated usernames**.
   - Attempt a **low-volume, stealthy brute-force** attack.

---

## TIP

Many organizations don’t **enforce a password change on first login**. If initial passwords are **guessable** and **not expired**, they remain a persistent vulnerability long after account creation. Always test whether **initial passwords still work** for stale accounts.

---

## Summary Table

| Vulnerability Type           | Description                                                         | Exploitable For                  |
|------------------------------|---------------------------------------------------------------------|----------------------------------|
| Predictable initial passwords | Passwords follow guessable or uniform pattern                      | Credential guessing, brute-force |
| User-password correlation     | Passwords derived from username or other attributes                | Account takeover                 |
| No forced password change     | Users may never change default passwords                           | Persistent access vector         |
