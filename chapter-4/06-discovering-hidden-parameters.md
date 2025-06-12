# Discovering Hidden Parameters

Some applications process hidden parameters that significantly influence application logic, such as:

```
?debug=true
```

These parameters are not visible in the application's content or URLs and must be discovered manually. They might alter behavior by:

* Disabling input validation
* Bypassing access controls
* Displaying verbose debug information

These parameters are typically not advertised (like `debug=false` in a visible URL). Their effect is only observable when the correct value is submitted.

### Hack Steps

1. Use common debug parameter names and values (e.g., `debug`, `test`, `hide`, `source` with `true`, `yes`, `on`, `1`).

   * Use Burp Intruder with the "cluster bomb" attack type to test permutations.
   * Test both in the URL and POST body.

2. Observe all responses for anomalies, such as:

   * Changes in layout or behavior
   * Debug output
   * Altered access or validation logic

3. Target critical functions (e.g., login, search, file upload/download), where developers are more likely to include debug logic.


