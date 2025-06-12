# Identifying Server-Side Functionality

Understanding how server-side functionality operates is a crucial part of mapping an application. Many server behaviors can be inferred by analyzing how client requests are structured and how the server responds. These clues often reveal potential vulnerabilities and implementation logic.

---

### Dissecting Requests to Infer Server Behavior

---

You can learn a lot from simply reviewing the structure of URLs and submitted parameters. These components often reflect the internal server logic, especially when developers expose raw implementation details.

#### Example 1: Java-Based Search Function

```
https://wahh-app.com/calendar.jsp?name=new%20applicants&isExpired=0&startDate=22%2F09%2F2010&endDate=22%2F03%2F2011&OrderBy=name
```

**Analysis:**

* The `.jsp` extension reveals that the app is likely using Java Server Pages.
* The `OrderBy` parameter strongly suggests that the request data is being passed directly into a SQL `ORDER BY` clause — a typical injection vector (see Chapter 9).
* The `isExpired=0` field appears to act as a Boolean filter. Changing it to `1` might expose restricted or expired data, potentially revealing an access control flaw (see Chapter 8).

#### Key Insight:

Understand how parameters map to SQL clauses, logic branches, or filters. If a parameter influences data visibility or sorting, it might be exploitable.

---

#### Example 2: ASP.NET File Handling with Templates

```
https://wahh-app.com/workbench.aspx?template=NewBranch.tpl&loc=/default&ver=2.31&edit=false
```

**Analysis:**

* `.aspx` indicates ASP.NET.
* The `template` and `loc` parameters seem to define a filename and directory, respectively. This strongly hints that the application reads files from disk.
* If these parameters are used without proper sanitization, path traversal attacks (e.g., `../../etc/passwd`) could be attempted (see Chapter 10).
* `edit=false` looks like a feature toggle — flipping it to `true` might enable hidden or unauthorized editing functionality.
* `ver=2.31` isn’t obviously useful, but version-specific behavior may exist.

#### Key Insight:

Any parameter affecting file or template names may indicate dynamic file inclusion or retrieval, which is high-risk if input isn’t validated.

---

#### Example 3: PHP-Based Email Submission

```
POST /feedback.php HTTP/1.1
Host: wahh-app.com
Content-Length: 389

from=user@wahh-mail.com&to=helpdesk@wahh-app.com&subject=Problem+logging+in&message=Please+help...
```

**Analysis:**

* `.php` confirms the use of PHP.
* Parameters like `from`, `to`, `subject`, and `message` likely get passed into an email handler or SMTP call.
* If user input is injected directly into email headers, this may be vulnerable to **email header injection**, or allow **unauthorized mail relay**.

#### Key Insight:

When input is passed to back-end systems like email servers or OS-level commands, strict input validation is critical — otherwise, injection vulnerabilities are likely.

---

### Interpreting RESTful or Rewritten URLs

Even when URLs don’t expose file extensions, their structure still reveals server logic.

---

#### Example: REST-Like Resource Access

```
http://eis/pub/media/117/view
```

This may be functionally equivalent to:

```
http://eis/manager?schema=pub&type=media&id=117&action=view
```

**Interpretation:**

* `media/117/view` suggests that resource ID 117 is being viewed.
* Changing `view` to `edit`, `delete`, or `add` might invoke additional functionality.
* To test for `add`, try a higher ID like `7337` to avoid ID conflicts:

```
http://eis/pub/media/7337/add
```

* You can also try changing `media` to other collections like `pages` or `users`:

```
http://eis/pub/users/1/view
```

#### Key Insight:

RESTful URL structures may conceal traditional parameter names but follow consistent logic — experiment with substituting verbs (actions) and nouns (resources).

---

### HACK STEPS


1. **Review all parameters in context:** Determine what each might control — filtering, sorting, file inclusion, feature toggles, etc.
2. **Analyze parameter values:** Look for Booleans (`true`, `false`, `0`, `1`), filenames, directories, or IDs — all are prime targets.
3. **Experiment with changes:** Toggle values, modify IDs, insert traversal sequences, or substitute known actions like `view` → `edit`.
4. **Identify signs of data-driven back-ends:** Parameters like `OrderBy`, `sort`, `filter`, and `limit` often map to SQL queries.
5. **Watch for injection or access control clues:** Where input changes visibility or behavior, explore further for privilege bypass or logic flaws.
6. **Don’t overlook generic-looking fields:** Even ambiguous parameters like `ver=2.31` might alter internal processing paths.
7. **Use a fuzzing strategy:** Try different verbs, resource names, and boundary values systematically.

---

By closely observing how requests are constructed and how the server responds, you can reverse-engineer large parts of the application’s behavior. This enables deeper enumeration, tailored attacks, and discovery of insecure functionality otherwise hidden from casual users.

This analysis is foundational for more advanced techniques covered in later chapters.
