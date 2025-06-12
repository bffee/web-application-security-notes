# 🕸️ Web Spidering

## 📌 Overview
- **Web spiders** automate the process of discovering content by recursively:
  1. Requesting a web page  
  2. Parsing it for links  
  3. Requesting those links  
  4. Repeating the process until no new content is found

## 🔍 Advanced Spidering Features
- **HTML Forms**: Spiders parse and submit forms with preset/random values to navigate multistage functionalities.
- **JavaScript Parsing**: Some spiders analyze client-side JavaScript to extract additional URLs.
- **Tools**:
  - **Burp Suite**
  - **WebScarab**
  - **Zed Attack Proxy (ZAP)**
  - **CAT**

## 📁 `robots.txt` Insight
- Located in the web root, it **lists URLs not to be indexed**.
- Often contains sensitive paths—attackers can use this file to seed spiders.
- **Security Implication**: `robots.txt` can be counterproductive if used to hide sensitive functionality.

## 🛒 Example: Extreme Internet Shopping (EIS)
- Without login, Burp Spider maps `/shop` and `/media`.
- `robots.txt` exposes:
  - `/mdsecportal`
  - `/site-old`  
  (Not linked anywhere else in the app)

## 📂 REST-style URLs
- REST uses parts of the **URL path** to represent unique resources.
- Traditional spiders work well here (e.g., `/shop/item123`, `/pub/doc45`).

---

## ⚠️ Limitations of Automated Spiders

### 1. ❌ Incomplete Coverage
- **Dynamic JavaScript navigation** may be missed.
- **Embedded objects** (e.g., Flash, Java applets) may contain unparsed links.

### 2. 🛑 Input Validation Roadblocks
- Forms often enforce **fine-grained validation**.
- A spider submitting invalid generic data may fail to proceed past forms.

### 3. 🔁 Same URL, Different Content
- Apps using **forms-based navigation** (e.g., POST to `/account.jsp`) with different parameters can confuse spiders.
- Many spiders avoid re-requesting the **same URL**, missing deeper functionality.
  - **Burp Spider** allows configuration to treat submissions with different parameters as unique.

### 4. ♾️ Infinite Spidering Loops
- URLs containing **volatile data** (e.g., timers, random seeds) cause spiders to believe they’re seeing new content continuously.

### 5. 🔐 Authentication Issues
- Requires manual setup of:
  - Session tokens
  - Login credentials
- Problems:
  - Spider may request logout or sensitive URLs → session termination
  - Invalid input → app ends session
  - Per-page tokens → out-of-sequence access breaks session

---

## 🚨 Warning: Spidering Can Be Dangerous
- Applications may expose sensitive functionality:
  - Delete users
  - Restart servers
  - Edit live content
- Spiders may **trigger dangerous actions** unintentionally.
- Example: CMS functionality discovered and used by a spider led to **real-time site defacement**.

---
---

# 🧭 User-Directed Spidering

## 📌 Overview
- A more sophisticated and controlled alternative to automated spidering.
- The user navigates the application using a browser as normal.
- All traffic is passed through a proxy/spider tool (e.g., Burp Suite, WebScarab).
- The tool:
  - Monitors requests and responses
  - Builds a site map
  - Parses responses to discover additional content

## ✅ Advantages Over Automated Spidering
- **Handles complex navigation**: The user can interact with JavaScript-based or non-standard navigation that automated spiders may miss.
- **Controlled input**: The user can ensure that all submitted data meets validation requirements.
- **Session stability**:
  - Users log in via the browser.
  - If the session breaks, the user can log in again and continue.
- **Safe handling of sensitive functionality**:
  - Links to sensitive functions (e.g., `deleteUser.jsp`) are identified in responses.
  - The user can choose whether to access them.

## 🛒 Example: Extreme Internet Shopping (EIS)
- **Problem with automated spider**:
  - Couldn't access `/home` because it's protected.
  - Received `302 Moved Temporarily` redirect to `/auth/Login?ReturnURL=/home/`.

- **Solution with user-directed spidering**:
  - User logs in via the browser.
  - The proxy/spider picks up the authenticated session.
  - Additional content becomes visible and is mapped.

- **Findings**:
  - New paths within the home menu system.
  - Example of JavaScript-launched content:
    ```html
    <a href="#" onclick="ui_nav('profile')">private profile</a>
    ```
  - Such dynamic links are often missed by traditional spiders.
  - The spider also found hidden paths like `/core/sitestats` from HTML comments, not visible in the UI.

## 🔧 Supporting Tools
- **Browser Extensions** (e.g., IEWatch):
  - Work within the browser UI.
  - Provide insight into:
    - HTTP headers
    - Request parameters
    - Cookies
    - Scripts, forms, and thick-client components
  - Useful for cross-verifying what the proxy/spider captures.

## 🧪 Hack Steps

1. **Configure your browser** to use Burp or WebScarab as a local proxy.
2. **Manually browse the application**:
   - Visit every discovered link or URL.
   - Submit all forms and complete multi-step processes.
   - Try different configurations:
     - JavaScript enabled/disabled
     - Cookies enabled/disabled
3. **Review the proxy/spider’s site map**:
   - Identify any functions or paths not browsed manually.
   - Determine how each was discovered (e.g., in Burp, check "Linked From").
   - Manually access those items in your browser to let the proxy parse their responses.
   - Repeat until no new content appears.
4. **Optional**: Perform automated spidering using the discovered content as seeds:
   - Exclude dangerous or session-breaking URLs from scope.
   - Run the spider and analyze newly discovered resources.

## 🗺️ Conclusion
- The resulting site map provides a detailed view of the application.
- Essential for identifying exposed attack surfaces during later testing.
