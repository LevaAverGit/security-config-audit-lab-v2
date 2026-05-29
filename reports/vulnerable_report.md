# Security Config Audit Report

## Target

- **URL:** http://localhost:8080
- **Mode:** vulnerable
- **Date:** 2026-05-24 17:41:10

## Executive Summary

| Field | Value |
|---|---|
| Total checks run | 15 |
| Failed / Warning | 10 |
| Passed | 5 |
| Risk score | 100/100 |
| Risk level | Critical |
| 🟠 High findings | 3 |
| 🟡 Medium findings | 3 |
| 🟢 Low findings | 4 |

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
- **Evidence:** `Server: nginx/1.25.5`
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

## Before/After Comparison


| Check | Vulnerable | Hardened |
|---|---|---|
| Security headers | ❌ Missing | ✅ Present |
| Debug endpoint `/debug` | ❌ Exposed, leaks env vars | ✅ Returns 404 |
| Demo config `/static/env-demo.txt` | ❌ Publicly accessible | ✅ Blocked (404) |
| PostgreSQL port 5432 | ❌ Exposed on host | ✅ Internal only |
| Directory listing `/static/` | ❌ Enabled | ✅ Disabled |
| Server version disclosure | ❌ May expose nginx version | ✅ server_tokens off |

> **Note:** Findings in this report represent **intentionally misconfigured** settings in a local educational lab. Run `hardened` mode to see the improved state.

## Limitations

- This is a local educational lab — not a production security audit.
- Checks are simplified and rule-based.
- This is not a penetration test.
- All credentials are fake/demo values.
- Results require manual validation before any action.
- Port checks only test localhost — not representative of network exposure.
