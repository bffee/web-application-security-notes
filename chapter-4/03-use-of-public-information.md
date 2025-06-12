# 🌐 Use of Public Information

## 📌 Overview
Even if functionality is no longer accessible from the app itself, **public repositories** like search engines and web archives may still contain references to it. These sources often reveal **old, hidden, or third-party-linked functionality**.

---

## 🔍 Useful Public Resources

### 1. **Search Engines**  
- Examples: **Google**, **Yahoo**, **Bing (MSN)**
- Index a wide range of web content, often retaining **cached copies** of removed pages.

### 2. **Web Archives**  
- Example: **[Wayback Machine](https://archive.org)**
- Hosts **historical snapshots** of websites across various dates.

---

## 🧭 Targeting Hidden or Third-Party Content

- Some resources may have been:
  - Previously linked internally but now hidden.
  - Linked **only from third-party websites** (e.g., business partner portals).
  - Indexed **before authentication requirements were added**.

---

## 🪜 Hack Steps – Search Engine and Archive Usage

1. **Use Multiple Public Sources**
   - Try several search engines and **web archives** to get full coverage.

2. **Leverage Google Dorking Techniques**
   - `site:target.com` → List all indexed pages.
   - `site:target.com login` → Focused search for keywords like login, admin, reset.
   - `link:target.com` → Finds external sites linking to the target (often includes third-party portals or old content).
   - `related:target.com` → May show discussion pages or similar apps.

3. **Use All Search Sections**
   - Check **Web**, **Groups**, **News**, and **Images** to find different types of indexed content.

4. **Enable Omitted Results**
   - Scroll to the end of search results → Click:
     > *"Repeat the search with the omitted results included"*

   - This disables Google’s result deduplication and might reveal near-duplicate but **distinct content**.

5. **View Cached Pages**
   - Even if a resource no longer exists or is behind auth:
     - Use Google's **cached** view to access old versions.
     - Check for removed functionality or internal naming conventions.

6. **Search Across All Domains**
   - The same organization may use multiple domains:
     - `targetcompany.com`, `dev.targetcompany.com`, `support.targetcompany.net`
   - Apply the same dorking and search logic across them.

---

## ⚠️ Why This Matters

- **Old but accessible functionality** may contain:
  - Unpatched vulnerabilities
  - Less secure legacy code
  - Credentials or logic flaws no longer present elsewhere
- Even removed content (from archives or caches) can point to:
  - Naming schemes
  - Parameter names
  - File structure
  - Internal endpoints still active

---

## 🧵 Developer Forum Intel Gathering

### Why It's Useful:
- Developers often post in forums seeking help on:
  - Bugs
  - Configuration issues
  - Stack traces
  - Source code snippets
  - Technology used (e.g., `Spring`, `Apache Struts`, etc.)

### Forums Include:
- Stack Overflow
- GitHub Issues
- Reddit programming/security subs
- Mailing lists or platform-specific help boards

---

## 🪜 Hack Steps – Forum and Dev Intel

1. **Build a Targeted Identity List**
   - Gather all relevant names/emails:
     - From HTML comments
     - `Author` meta tags
     - Contact pages on the target domain
     - Error messages
     - Forum posts mentioning the company/app

2. **Search for Developer Activity**
   - Query dev names/emails using:
     - `"Name" site:stackoverflow.com`
     - `"Name" inurl:github.com/issues`
     - `"email@example.com" filetype:log`
   - Review:
     - Technologies mentioned
     - Design/implementation problems
     - Snippets of source code or config files
     - Clues about internal structure and known vulnerabilities

---

## 🧠 Summary

| Resource Type            | Use Case                                                                 |
|--------------------------|--------------------------------------------------------------------------|
| Google/Other Search Engines | Find old, unlinked, or third-party-exposed pages                       |
| Google Dorks             | Narrow down content types (login pages, admin panels, etc.)             |
| Wayback Machine          | View historical snapshots and previously public files                   |
| Cached Pages             | Access removed or restricted content                                     |
| Forum Posts              | Get insider knowledge on app structure and vulnerabilities              |
| Developer Intel          | Reveal tech stack, internal practices, and potential security issues    |
| Cross-domain Search      | Find related content on alternate org-owned domains                     |

