# Predictable Tokens

* Session tokens may not reveal user data directly but can still be predictable.
* Attackers can use partial samples to guess other valid tokens.
* Even with a low success rate (e.g., 1 in 1000), automated tools can brute-force valid sessions.

---

### Remote vs Lab Testing

* **Remote Targets**:

  * **Limited token samples**.
  * Affected by **bandwidth**, **latency**, and **user activity**.

* **Lab Testing**:

  * Can generate **millions of tokens**.
  * **No interference**; easier to identify patterns.

---

### Sequential Tokens

* Some applications use **incrementing numbers** as session tokens.
* Just 2-3 tokens may be enough to guess the full sequence.
* **Indicators of a valid session**:

  * **Length of HTTP response**.
  * **User-identifying data leaks** (e.g., usernames), extractable using tools like **Burp Intruder**.

---

## 1. Concealed Sequences

### Observation

* Tokens may **look random** but are actually encoded sequences (often Base64).
* Example token list:

```
lwjVJA
Ls3Ajg
xpKr+A
XleXYg
9hyCzA
jeFuNg
JaZZoA
```

### Step-by-Step Analysis

1. Decode tokens from **Base64** → binary output with non-printable characters.
2. Convert binary to **hex**:

```
9708D524
2ECDC08E
C692ABF8
5E579762
F61C82CC
8DE16E36
25A659A0
```

3. Subtract consecutive values:

```
FF97C4EB6A
97C4EB6A
FF97C4EB6A
97C4EB6A
FF97C4EB6A
FF97C4EB6A
```

### Conclusion

* Fixed delta: each token = previous + `0x97C4EB6A`
* Truncated to 32-bit, then Base64-encoded for transport.

### Attack Strategy

* Once delta is known:

  * Reconstruct earlier tokens.
  * Predict future session tokens.
  * Scripted attacks become feasible.

> ⚠️ Encoded tokens may still be predictable under the hood. Always test for patterns.

---

## 2. Time Dependency

### Observation

* Some applications embed the **current time** in session tokens.
* If other entropy is low, tokens can become **predictable based on timestamp alone**.

### Example Sequence

```
3124538-1172764258718
3124539-1172764259062
3124540-1172764259281
3124541-1172764259734
3124542-1172764260046
3124543-1172764260156
3124544-1172764260296
3124545-1172764260421
3124546-1172764260812
3124547-1172764260890
```

* **First number** increments by 1 (easy to predict).
* **Second number** varies, but shows temporal progression.
* Difference between timestamps:

```
344, 219, 453, 312, 110, 140, 125, 391, 78
```

Brute-forcing over this small numeric range is feasible, especially when the token format is partially known or timestamp boundaries are predictable.

### Later Sample (after delay)

```
3124553-1172764800468
3124554-1172764800609
3124555-1172764801109
3124556-1172764801406
3124557-1172764801703
3124558-1172764802125
3124559-1172764802500
3124560-1172764802656
3124561-1172764803125
3124562-1172764803562
```

### Key Observations

* Only 5 tokens skipped → tokens issued to other users.
* Second part jumped by \~539,578 → likely a **timestamp in milliseconds**.

### Confirmed Generation Logic

```java
String sessId = Integer.toString(s_SessionIndex++)
              + "-"
              + System.currentTimeMillis();
```

### Attack Strategy

* Keep polling the server for new tokens.
* When index skips (e.g., +2 instead of +1), know a token was issued to someone else.
* Use previous and next token to define **timestamp bounds**.
* Brute-force the range to guess missing token:

  * Append guessed timestamp to skipped index.
  * Use each guess to access a protected resource.
  * Stop when access is successful (session hijacked).
* 🛡️ **Note**: Consider **rate limiting** and delays in production environments during brute-force attempts.

> This can be automated to steal all user sessions, including admins.

---

## 3. Weak Random Number Generation

### Observation

* **Lack of true randomness**: PRNGs (pseudorandom generators) can be predictable.
* If PRNG is used for tokens, attackers may **reverse/forward-calculate** the sequence.

### Case Study: Jetty Server

* **Implementation**: Used `java.util.Random` for session tokens.
* **Underlying algorithm**: Linear congruential generator:

```java
synchronized protected int next(int bits) {
  seed = (seed * 0x5DEECE66DL + 0xBL) & ((1L << 48) - 1);
  return (int)(seed >>> (48 - bits));
}
```

* **Vulnerability**: One output reveals generator state → predict all outputs.

### Developer Pitfall

* **Concatenated PRNG outputs** don't improve security.
* Revealing multiple consecutive outputs may expose internal PRNG state.

### Other Frameworks

* **PHP ≤ 5.3.2** used:

  * **Client IP**
  * **Epoch time & microseconds**
  * **PRNG seeded from process start time**
* **Exploitation**: Attacker can guess inputs if app leaks IP/time hints.
* **Tool**: `phpwn` by Samy Kamkar (2010) automates this.

> 🧠 Even simple RNGs are dangerous if the attacker can guess the state.

---

### Testing Randomness

#### **Overview**

* Use **statistical hypothesis testing** to detect non-random patterns.

#### **Tool: Burp Sequencer**

* Automates entropy testing (character-level and bit-level).
* Outputs an **effective entropy** score.

#### **Steps to Use**

1. **Identify token-issuing request** (e.g., login).
2. **Send to Burp Sequencer**.
3. **Configure token location**.
4. **Start live capture** or load from file.
5. **Enable auto analysis**.
6. Minimum **500 tokens** recommended; **20,000** for FIPS compliance.

#### **Key Insights**

* Tokens may **fail tests but still be secure** in practice.
* Tokens may **pass tests but still be predictable** under specific logic.
* Use detailed test output to find localized entropy weaknesses.

> 🔍 Look at both **individual** and **overall** entropy to assess token robustness.

---

### Caveats

* **False sense of security**: Random-looking ≠ unpredictable.
* **Deterministic algorithms**: Can pass randomness tests but be reversible.
* **Low entropy ≠ exploitability**: Failing tokens aren't always practically guessable.
* Use entropy analysis as a **starting point**, not a final verdict.
* Even tokens that pass entropy tests may need **manual reverse-engineering** if they include predictable elements.

---

## Hack Steps

1. **Locate token issuance points**

   * Find requests that generate session tokens (e.g., GET /, login, registration).

2. **Capture tokens using Burp Sequencer**

   * Configure token location.
   * Prefer fast capture to avoid skipped tokens (important in remote testing).

3. **Analyze token randomness**

   * Enable **Auto Analyze**.
   * Wait for at least **500 tokens** for basic confidence.

4. **Review results**

   * Focus on **effective entropy bits**.
   * Look for repeating sequences, low variance, or partial leaks.

5. **Cross-user analysis**

   * Repeat tests from different IPs/users.
   * Check whether tokens show global patterns.

6. **Custom automation**

   * If a predictable pattern emerges, script token generation logic.

7. **Code review (if source is available)**

   * Identify entropy sources (e.g., time, IP, PRNG).
   * Check if brute-force or prediction is feasible.
