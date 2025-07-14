# Log, Monitor, and Alert

Session management should integrate tightly with the application’s **logging and alerting mechanisms** to detect attacks and support defensive responses.

---

## Monitoring Invalid Tokens

- Log and monitor requests using **invalid session tokens**:
  - Brute-force guessing attacks leave behind **numerous failed attempts**.
- **Rate-limiting** or blocking based on:
  - Number of failed token uses per **IP address**
  - Frequency of anomalous requests

> NOTE: Blocking based on IP can be unreliable due to:
> - Shared IPs (e.g., behind NAT or corporate proxies)
> - Changing IPs (e.g., mobile users or ISPs like AOL)

---

## Alerting and Forensics

- Generate **alerts for suspicious session behavior**:
  - Concurrent logins
  - Per-page token mismatches (possible hijacking)
- Users should be notified about session anomalies.
  - Even if a compromise occurred, the user can **review activity** and take action.

---

## Reactive Session Termination

- In **high-security environments**, terminate the session for:
  - Modified form fields or query parameters
  - Requests containing SQLi or XSS payloads
  - Inputs violating client-side validation (e.g., length, format)
- Benefits:
  - Disrupts **automated attacks** and slows down probing
  - Makes discovering residual vulnerabilities **much harder**

> TIP: This mechanism should be **disabled during testing or pentesting**, as it:
> - Severely limits tester efficiency
> - Risks hiding real vulnerabilities due to test interference

---

## Automation Workarounds for Testers

If the application uses forced logouts:

- In **Burp Intruder**:
  - Use **Obtain Cookie** to log in before each test and use fresh tokens.
- In **Burp Proxy**:
  - Build an extension using `IBurpExtender` to:
    - Detect forced logouts
    - Automatically reauthenticate
    - Resume the session and notify the tester

---

## Summary Table

| Defensive Measure                     | Goal                                                       |
|--------------------------------------|------------------------------------------------------------|
| Monitor invalid session tokens       | Detect brute-force and enumeration attempts                |
| Alert on session anomalies           | Inform users of potential hijacking or concurrent access   |
| Terminate on suspicious input        | Disrupt common attack techniques like SQLi and XSS         |
| Log detailed session activity        | Aid incident response and forensic investigation           |
| Disable defensive termination in test| Avoid interference during legitimate penetration testing   |

