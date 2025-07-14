# Testing Multistage Processes

Access control vulnerabilities may be hidden within **multistep workflows**. In these cases, each step of a sensitive function (e.g., adding a user, making a payment) may span **multiple sequential requests**, each potentially vulnerable on its own.

Simply replaying individual requests from a site map often fails due to missing session state or request sequence dependencies — meaning **you must test each stage independently**.

---

## Key Testing Concepts

- **Each stage of a multistep process** (form display, data submission, confirmation) should have **its own access controls**.
- Don’t assume an application enforces checks at every stage just because it does so at the beginning.
- Developers may **implicitly trust users** who reach later stages, creating bypass opportunities.

> 💡 Multistage vulnerabilities are common even in **high-security apps** like online banking.

---

## Example Scenario

A form to add a user may span:
1. Load form interface (`GET`)
2. Submit user details (`POST`)
3. Confirm submission (`POST/GET`)
   
Even if the form page is protected, the **submission or confirmation endpoints** may be unguarded — enabling privilege escalation if accessed directly.

---

## Hack Steps

1. **Test Every Request Individually**:
   - Include redirects, form submissions, and even **unparameterized** requests.
   - Switch between user roles (admin, regular user, guest) during tests.

2. **Break Assumptions About Legitimate Flow**:
   - Try accessing later stages of a process directly with a **low-privileged account**.
   - Look for cases where the app assumes prior access checks imply future legitimacy.

3. **Manual Session Switching**:
   - Walk through the full process as a privileged user.
   - Then replay the same requests as a lower-privileged user by switching session cookies using your proxy.

4. **Use Burp’s "Request in Browser"**:
   - **a.** Perform the multistage process as a privileged user.
   - **b.** Identify all related requests in **Burp Proxy history**.
   - **c.** Log in via a **different browser** as a low-privileged user.
   - **d.** For each request, choose **"Request in browser in current browser session"**.
   - **e.** Paste the generated Burp URL into the lower-privileged browser.
   - **f.** Observe whether the privileged action executes.

> 🔧 Burp uses a local redirection trick to replay the original request **with the current browser’s session** (i.e., cookie remains unchanged but request gets injected).

---

## Testing Tips

- Use **different browsers or machines** to test different user sessions simultaneously (cookies are shared per browser instance).
- Create **multiple Burp listeners** to map each browser’s traffic and isolate session flows.
- Compare sequences **side-by-side** to detect missing access checks or inconsistent behavior.

> 🧠 Comparing requests across user roles often reveals unexpected authorization gaps.

---
