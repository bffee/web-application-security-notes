# Log, Monitor, and Notify

Authentication-related activity must be logged and monitored to detect attacks and inform both administrators and users of suspicious behavior.

## Logging Authentication Events

- Log **all authentication-related actions**, including:
  - Login and logout
  - Password change and reset
  - Account suspension
  - Account recovery

- Include relevant metadata:
  - **Username**
  - **Source IP address**
  - **Timestamps**
  - **Outcome (success/failure)**

> **IMPORTANT:** Logs must **never include security-sensitive data**, such as plaintext passwords.

- Logs must be **secured against unauthorized access** to avoid leaks and tampering.

---

## Real-Time Monitoring and Alerting

- Feed authentication logs into **real-time intrusion detection or alerting systems**.
- Detect and escalate suspicious patterns such as:
  - Rapid repeated login failures (brute-force attack indicators)
  - Logins from unfamiliar geolocations or IP ranges

> **TIP:** Timely detection enables active defense—rate limiting, IP banning, or forced re-authentication.

---

## User Notifications

### Out-of-Band Notifications

- For **critical security events**, notify users via **out-of-band channels** (e.g., email):
  - Password changes
  - Password resets
  - Account recovery or reactivation

### In-Band Notifications

- For **frequent or session-based events**, notify users during normal application use:
  - After login, display:
    - Last successful login (time and IP/domain)
    - Number of failed login attempts since last successful login

> **BENEFIT:** When users are aware of unusual access attempts, they’re more likely to:
  - Change their passwords
  - Use stronger passwords
  - Report potential compromise

---

# Summary Table

| Topic                        | Best Practice                                                                |
|------------------------------|------------------------------------------------------------------------------|
| Event Logging                | Log all auth-related events; include metadata, exclude secrets               |
| Log Security                 | Protect logs from unauthorized access                                        |
| Intrusion Detection          | Monitor logs in real-time for brute-force and anomalies                      |
| Out-of-Band User Alerts      | Notify users via email for password changes, resets, and recovery            |
| In-Band Session Notifications| Show last login and failed attempts post-login                               |
