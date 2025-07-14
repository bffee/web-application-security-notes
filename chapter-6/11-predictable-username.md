# Predictable Usernames

Some web applications automatically generate usernames using a **predictable naming scheme** (e.g., `cust5331`, `cust5332`, etc.). This behavior significantly **lowers the barrier** for attackers to discover valid usernames.

Unlike traditional **username enumeration** methods that rely on **repeated interactions** with the application (and often raise suspicion or trigger rate limiting), this technique is **nonintrusive** and requires **minimal interaction** to be successful.

---

## Why This Is a Problem

### 1. Mass User Discovery
- If a **predictable sequence** is used, an attacker can quickly deduce the entire set of **valid usernames** just by observing a few values.
- Once the pattern is known, attackers can:
  - Generate a complete list of **usernames**.
  - Use the list for **brute-force attacks**, **credential stuffing**, or other attacks requiring a known username.

### 2. Silent Enumeration
- This form of discovery doesn’t require **sending login requests**.
- Therefore, the attacker avoids triggering:
  - **Account lockouts**
  - **Rate limiting**
  - **Logging alerts**
- This stealth approach makes detection by defenders much harder.

---

## HACK STEPS

1. **Identify auto-generated usernames**:
   - Register multiple test accounts in quick succession.
   - Look for a **pattern or incrementing identifier** in the usernames.

2. **If a pattern is detected**:
   - **Extrapolate backwards and forwards** to generate a list of possible valid usernames.
   - Use the generated list in:
     - **Brute-force login attacks**
     - **Access control testing** (see Chapter 8)
     - **Social engineering attempts**

---

## TIP

If the application displays or uses **numeric identifiers** (e.g., in URLs or usernames), consider whether they **map directly to user accounts**. Even if the visible username is not predictable, the underlying ID may be, and that ID could be leveraged for **indirect user enumeration**.

---

## Summary Table

| Vulnerability Type       | Description                                                       | Exploitable For               |
|--------------------------|-------------------------------------------------------------------|-------------------------------|
| Predictable usernames    | Automatically generated usernames follow a predictable pattern    | Stealth enumeration, brute-force |
| Minimal interaction      | No need for repeated login attempts or error analysis             | Silent reconnaissance         |
