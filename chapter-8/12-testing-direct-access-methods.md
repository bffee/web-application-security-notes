# Testing Direct Access to Methods

Some applications expose **server-side API methods** directly (e.g., servlets, internal Java classes) which can often be **invoked via crafted requests**. If these methods are insufficiently protected by access controls, they become an easy target for unauthorized access and privilege escalation.

This section focuses on identifying and testing these **exposed backend methods**, especially when **Java method naming patterns** or **package-style parameters** are visible in requests.

---

## Core Idea

Even if most APIs are protected, **some internal or debug interfaces** may be exposed inadvertently. Attackers can find and invoke such methods directly using predictable naming patterns and URL parameters.

### Example

```http
POST /svc HTTP/1.1
Host: wahh-app
Content-Length: 37

servlet=com.ibm.ws.webcontainer.httpsession.IBMTrackerDebug
```

In this example, the servlet name hints at a well-known internal component. By **brute-forcing similar servlet or method names**, an attacker may discover additional accessible functionalities.

---

## Hack Steps

1. **Identify Java-Like Method Names**
   - Look for parameters that follow common Java naming conventions:
     - `getBalance`, `setRole`, `addUser`, `updatePermissions`, `isExpired`, `hasAccess`
   - Also flag those that follow a **package path** structure:
     - `com.company.module.ClassName`

2. **Look for Method Enumeration**
   - Check proxy history for requests that may list available interfaces or methods.
   - If not already seen, try guessing typical introspection method names like:
     - `listInterfaces`, `listMethods`, `getAvailableMethods`

3. **Use Public Resources**
   - Search online (forums, bug bounty writeups, GitHub, etc.) for well-known or default method names associated with the underlying platform or product.

4. **Guess Other Methods**
   - Use naming patterns and information from Chapter 4 to guess method names, especially those similar to existing ones.

5. **Access with Various Roles**
   - Try invoking the discovered methods as:
     - Admin user
     - Regular user
     - Unauthenticated user
   - Observe any unauthorized access to privileged actions.

6. **Target Low-Argument Methods**
   - If you don’t know the argument structure, test methods likely to take **no or few arguments** such as:
     - `getAllUsers`, `getAllRoles`, `listInterfaces`, `getCurrentUser`

---

## TIP

> Java-based backends often **leak method names** in client-side code, debug logs, or predictable patterns. Even if authentication is required, **access control checks may not be consistently applied across all exposed APIs**.

---

## Common API Targets

- `/svc`, `/services`, `/method`, `/action`, `/controller`
- `*.do`, `*.jsp`, `*.action`, or anything with `class=`, `method=`, `interface=`
- Java Enterprise features or libraries (e.g., IBM WebSphere, Apache Axis)

---

