# Security Config Audit Report

## Target

- **URL:** http://localhost:8080
- **Mode:** vulnerable
- **Date:** 2026-09-11 03:23:02

## Executive Summary

| Field | Value |
|---|---|
| Total checks run | 20 |
| Failed / Warning | 13 |
| Passed | 7 |
| Risk score | 100/100 |
| Risk level | Critical |
| 🟠 High findings | 3 |
| 🟡 Medium findings | 5 |
| 🟢 Low findings | 5 |

## Findings

### ❌ HDR-CSP — Missing header: Content-Security-Policy

- **Severity:** 🟡 Medium
- **Status:** failed
- **Description:** The HTTP response does not include the Content-Security-Policy header.
- **Evidence:** `Header 'Content-Security-Policy' not present in response from http://localhost:8080`
- **Risk:** Browser security controls may not be enforced.
- **Recommendation:** Add 'Content-Security-Policy' to server or nginx configuration.

### ❌ HDR-XFO — Missing header: X-Frame-Options

- **Severity:** 🟡 Medium
- **Status:** failed
- **Description:** The HTTP response does not include the X-Frame-Options header.
- **Evidence:** `Header 'X-Frame-Options' not present in response from http://localhost:8080`
- **Risk:** Browser security controls may not be enforced.
- **Recommendation:** Add 'X-Frame-Options' to server or nginx configuration.

### ❌ HDR-XCTO — Missing header: X-Content-Type-Options

- **Severity:** 🟢 Low
- **Status:** failed
- **Description:** The HTTP response does not include the X-Content-Type-Options header.
- **Evidence:** `Header 'X-Content-Type-Options' not present in response from http://localhost:8080`
- **Risk:** Browser security controls may not be enforced.
- **Recommendation:** Add 'X-Content-Type-Options' to server or nginx configuration.

### ❌ HDR-RP — Missing header: Referrer-Policy

- **Severity:** 🟢 Low
- **Status:** failed
- **Description:** The HTTP response does not include the Referrer-Policy header.
- **Evidence:** `Header 'Referrer-Policy' not present in response from http://localhost:8080`
- **Risk:** Browser security controls may not be enforced.
- **Recommendation:** Add 'Referrer-Policy' to server or nginx configuration.

### ❌ HDR-PP — Missing header: Permissions-Policy

- **Severity:** 🟢 Low
- **Status:** failed
- **Description:** The HTTP response does not include the Permissions-Policy header.
- **Evidence:** `Header 'Permissions-Policy' not present in response from http://localhost:8080`
- **Risk:** Browser security controls may not be enforced.
- **Recommendation:** Add 'Permissions-Policy' to server or nginx configuration.

### ❌ SRV-001 — Server version disclosed

- **Severity:** 🟢 Low
- **Status:** failed
- **Description:** The Server header reveals software version information.
- **Evidence:** `Server: nginx/1.25.3`
- **Risk:** Version disclosure aids fingerprinting and targeted attacks.
- **Recommendation:** Set 'server_tokens off' in nginx.conf.

### ❌ ENV-001 — Demo config file accessible: /static/env-demo.txt

- **Severity:** 🟠 High
- **Status:** failed
- **Description:** A configuration/demo file is publicly accessible at http://localhost:8080/static/env-demo.txt
- **Evidence:** `HTTP 200 — contains sensitive-looking demo values`
- **Risk:** Exposed demo configs reveal patterns used in real configs and may expose secrets if misconfigured.
- **Recommendation:** Remove or restrict access to config/env files. Block via nginx location rule.

### ✅ ENV-001 — Demo config not accessible: /env-demo.txt

- **Severity:** 🟠 High
- **Status:** passed
- **Description:** /env-demo.txt returned HTTP 404
- **Evidence:** `HTTP 404 for http://localhost:8080/env-demo.txt`

### ✅ ENV-001 — Demo config not accessible: /.env

- **Severity:** 🟠 High
- **Status:** passed
- **Description:** /.env returned HTTP 404
- **Evidence:** `HTTP 404 for http://localhost:8080/.env`

### ✅ ENV-001 — Demo config not accessible: /.env.demo

- **Severity:** 🟠 High
- **Status:** passed
- **Description:** /.env.demo returned HTTP 404
- **Evidence:** `HTTP 404 for http://localhost:8080/.env.demo`

### ❌ DBG-001 — Debug endpoint accessible and exposes config

- **Severity:** 🟠 High
- **Status:** failed
- **Description:** /debug is publicly accessible (HTTP 200) and appears to expose environment/config information.
- **Evidence:** `HTTP 200 for http://localhost:8080/debug; response contains debug indicators: True`
- **Risk:** Exposed debug endpoints may leak environment variables, credentials, and system info.
- **Recommendation:** Disable debug endpoint in production. Return 404 or remove the route entirely.

### ✅ DIR-001 — Directory listing not detected

- **Severity:** 🟡 Medium
- **Status:** passed
- **Description:** /static/ does not appear to expose a directory listing.
- **Evidence:** `HTTP 404 — no listing indicators found`

### ❌ PORT-001 — PostgreSQL port 5432 exposed on host

- **Severity:** 🟠 High
- **Status:** failed
- **Description:** Port 5432 (PostgreSQL) is accessible on localhost.
- **Evidence:** `TCP connection to localhost:5432 succeeded`
- **Risk:** Exposed database ports increase attack surface. Direct access enables brute-force and exploitation attempts.
- **Recommendation:** Remove port mapping from docker-compose.yml. Database should only be accessible within the Docker network.

### ❌ HSTS-001 — HSTS header missing

- **Severity:** 🟡 Medium
- **Status:** failed
- **Description:** The Strict-Transport-Security header is not present.
- **Evidence:** `Header 'Strict-Transport-Security' not found in response from http://localhost:8080`
- **Risk:** Without HSTS, browsers may connect over HTTP, enabling downgrade attacks.
- **Recommendation:** Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to nginx configuration.

### ✅ CORS-001 — CORS header absent

- **Severity:** 🟢 Low
- **Status:** passed
- **Description:** No Access-Control-Allow-Origin header present — cross-origin requests are not explicitly permitted.
- **Evidence:** `Header 'Access-Control-Allow-Origin' not present in response`

### ❌ COOKIE-001 — Cookie missing security flags: Secure, HttpOnly, SameSite

- **Severity:** 🟡 Medium
- **Status:** failed
- **Description:** A cookie is set without one or more of the Secure, HttpOnly, and SameSite attributes.
- **Evidence:** `Set-Cookie: session=demo-session-value`
- **Risk:** Missing HttpOnly exposes the cookie to theft via XSS; missing Secure allows it to travel over plain HTTP; missing SameSite enables CSRF.
- **Recommendation:** Set 'Secure; HttpOnly; SameSite=Strict' on session cookies.

### ⚠️ WAF-001 — No WAF detected in front of the application

- **Severity:** 🟢 Low
- **Status:** warning
- **Description:** An obvious XSS/SQLi payload was not blocked; no web application firewall appears to be filtering requests.
- **Evidence:** `Attack payload returned HTTP 200 (expected 403/406 if a WAF were present)`
- **Risk:** Without a WAF, exploit attempts reach the application directly, removing a layer of defence-in-depth.
- **Recommendation:** Deploy a WAF such as ModSecurity with the OWASP Core Rule Set in front of the app (see docs/WAF.md).

### ✅ HTTP-METHODS-001 — No dangerous HTTP methods enabled

- **Severity:** 🟢 Low
- **Status:** passed
- **Description:** The server does not advertise TRACE, TRACK, CONNECT, PUT, or DELETE.
- **Evidence:** `Allow: OPTIONS, HEAD, GET`

### ❌ HTTPS-REDIRECT-001 — HTTP is not redirected to HTTPS

- **Severity:** 🟡 Medium
- **Status:** failed
- **Description:** Plain HTTP request returned HTTP 200 without redirecting to HTTPS.
- **Evidence:** `HTTP 200, no Location header`
- **Risk:** Traffic served over plain HTTP can be intercepted or modified (MITM) and is exposed to SSL-stripping downgrade attacks.
- **Recommendation:** Configure the web server to 301-redirect all HTTP traffic to HTTPS, and pair it with HSTS.

### ✅ XPB-001 — X-Powered-By header absent

- **Severity:** 🟢 Low
- **Status:** passed
- **Description:** No X-Powered-By header in response.
- **Evidence:** `X-Powered-By header not present`

## Before/After Comparison


| Check | Vulnerable | Hardened |
|---|---|---|
| Security headers | ❌ Missing | ✅ Present |
| Debug endpoint `/debug` | ❌ Exposed, leaks env vars | ✅ Returns 404 |
| Demo config `/static/env-demo.txt` | ❌ Publicly accessible | ✅ Blocked (404) |
| PostgreSQL port 5432 | ❌ Exposed on host | ✅ Internal only |
| Session cookie flags | ❌ No Secure/HttpOnly/SameSite | ✅ Secure; HttpOnly; SameSite=Strict |
| Server version disclosure | ❌ May expose nginx version | ✅ server_tokens off |

> **Note:** Findings in this report represent **intentionally misconfigured** settings in a local educational lab. Run `hardened` mode to see the improved state.

## Limitations

- This is a local educational lab — not a production security audit.
- Checks are simplified and rule-based.
- This is not a penetration test.
- All credentials are fake/demo values.
- Results require manual validation before any action.
- Port checks only test localhost — not representative of network exposure.
