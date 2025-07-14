# Incomplete Validation of Credentials

Some web applications implement weak or flawed password validation logic, undermining even strong user-selected passwords. These implementations may fail to fully process all password characters or transform them in insecure ways before validation, reducing the effective password space and enabling easier brute-force or guessing attacks.

---

## Common Validation Flaws

### 1. Password Truncation
- The application **only validates the first n characters** of a password.
- Example:  
  If a password is `SuperSecure123!`, and only the first 8 characters are validated, any password starting with `SuperSec` will be accepted.

### 2. Case-Insensitive Matching
- The application **ignores character casing** during password validation.
- Example:  
  Passwords like `Password`, `PASSWORD`, and `password` are treated the same.

### 3. Character Stripping
- Some applications **strip special characters** or certain typographical characters before validation.
- This is often a result of:
  - Misguided input sanitization
  - Encoding issues
  - Lack of understanding of password processing requirements

### 4. Real-World Occurrence
- These validation issues have been found in **high-profile applications**.
- Usually discovered through **manual experimentation** or bug bounty research.
- Attackers exploit these limitations to **reduce attack complexity**.

---

## Security Impact

- Reduces **effective password entropy**:
  - E.g., 12-character password behaves like 8-character one.
- Enables attackers to **optimize brute-force attacks**:
  - Fewer permutations to test
  - Higher chance of guessing valid credentials
- Weakens otherwise strong passwords set by users

---

## HACK STEPS

1. **Test login behavior using your own account**:
   - Attempt the following variations on your real password:
     - Remove the last character
     - Modify character casing
     - Remove or replace special characters (e.g., `!`, `@`, `#`)
   - Observe which variations are still accepted.

2. **Analyze validation logic**:
   - Continue experimenting to determine whether truncation, case insensitivity, or character stripping is occurring.
   - Use Burp Suite's **Repeater** to replay modified login requests efficiently.

3. **Optimize password attack payloads**:
   - If truncation or transformation is confirmed, tailor your brute-force or dictionary lists to:
     - Use fewer permutations
     - Focus only on validated segments
   - This dramatically increases attack efficiency and success probability.

---

## TIP

Don’t assume complex password policies mean strong enforcement. Validate what the server **actually enforces**, not just what the UI requires. Often, frontend validation is stricter than backend enforcement. Submitting modified passwords via direct HTTP requests (e.g., using Burp Repeater) bypasses client-side checks entirely.

---

## Summary Table

| Weak Validation Type     | Description                                               | Impact                              |
|--------------------------|-----------------------------------------------------------|-------------------------------------|
| Truncation               | Only first n characters are validated                     | Shortens effective password length  |
| Case-insensitive checks  | Ignores differences in upper/lower case                   | Reduces password space              |
| Character stripping      | Removes special or typographic characters before checking | Weakens strong user-selected input  |
