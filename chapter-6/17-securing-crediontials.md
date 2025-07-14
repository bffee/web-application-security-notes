# Securing Authentication

Implementing a secure authentication mechanism involves balancing multiple, often conflicting goals. Enhancing security may negatively impact usability or increase implementation costs. In some cases, excessive security measures may even backfire—for example, overly strict password policies often cause users to write down their passwords.

## Key Trade-Off Considerations

To strike an effective balance between security, usability, and cost, the following factors should be considered:

- **Security Criticality**: How sensitive is the functionality and data being protected?
- **User Tolerance**: To what extent will users cooperate with strong authentication requirements?
- **Support Costs**: What is the cost of maintaining a system that is less user-friendly?
- **Financial Viability**: Is it cost-effective to implement stronger alternatives based on the value of protected assets?

In many real-world cases, application designers accept certain threats as inherent risks and focus on defending against the most serious ones.

---

# Use Strong Credentials

Strong credentials form the foundation of secure authentication. The following practices are recommended:

## Password Requirements

- Enforce a minimum length.
- Require inclusion of:
  - Alphabetic characters
  - Numeric characters
  - Typographic/special characters
  - Both uppercase and lowercase letters
- Prevent use of:
  - Dictionary words
  - Common passwords
  - Names
  - Passwords identical to the username
  - Passwords similar to previously used ones

> **TIP:** Different user types may justify different password complexity rules depending on the access and risk level.

## Username Management

- Ensure all usernames are unique.
- For system-generated credentials:
  - Use random generation with sufficient entropy.
  - Prevent generation patterns that could be guessed, even with access to a large number of samples.

## Password Flexibility

- Allow users to set long passwords.
- Support a wide range of allowable characters for increased password strength and flexibility.

---

# Summary Table

| Category              | Best Practice Summary                                                           |
|-----------------------|----------------------------------------------------------------------------------|
| Password Complexity   | Enforce length and character diversity, and block weak or reused passwords       |
| Username Management   | Ensure uniqueness and high-entropy system-generated values                      |
| Password Flexibility  | Allow long passwords and a wide character range                                 |
| Design Considerations | Balance security with usability, support effort, and asset value                |
