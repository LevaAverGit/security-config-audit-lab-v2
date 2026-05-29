# Security Config Audit Report

## Target

- **URL:** http://localhost:8081
- **Mode:** hardened
- **Date:** 2026-05-24 17:41:19

## Executive Summary

| Field | Value |
|---|---|
| Total checks run | 15 |
| Failed / Warning | 1 |
| Passed | 14 |
| Risk score | 15/100 |
| Risk level | Low |
| 🟡 Medium findings | 1 |

## Findings

### ✅ HDR-CSP — Header present: Content-Security-Policy

- **Severity:** 🟡 Medium
- **Status:** passed
- **Description:** Content-Security-Policy is present.
- **Evidence:** `Content-Security-Policy: default-src 'self'`

### ✅ HDR-XFO — Header present: X-Frame-Options

- **Severity:** 🟡 Medium
- **Status:** passed
- **Description:** X-Frame-Options is present.
- **Evidence:** `X-Frame-Options: DENY`

### ✅ HDR-XCTO — Header present: X-Content-Type-Options

- **Severity:** 🟢 Low
- **Status:** passed
- **Description:** X-Content-Type-Options is present.
- **Evidence:** `X-Content-Type-Options: nosniff`

### ✅ HDR-RP — Header present: Referrer-Policy

- **Severity:** 🟢 Low
- **Status:** passed
- **Description:** Referrer-Policy is present.
- **Evidence:** `Referrer-Policy: no-referrer`

### ✅ HDR-PP — Header present: Permissions-Policy

- **Severity:** 🟢 Low
- **Status:** passed
- **Description:** Permissions-Policy is present.
- **Evidence:** `Permissions-Policy: geolocation=(), microphone=(), camera=()`

### ✅ SRV-001 — Server header present but no version

- **Severity:** 🟢 Low
- **Status:** passed
- **Description:** Server header present without version disclosure.
- **Evidence:** `Server: nginx`

### ✅ ENV-001 — Demo config not accessible: /static/env-demo.txt

- **Severity:** 🟠 High
- **Status:** passed
- **Description:** /static/env-demo.txt returned HTTP 404
- **Evidence:** `HTTP 404 for http://localhost:8081/static/env-demo.txt`

### ✅ ENV-001 — Demo config not accessible: /env-demo.txt

- **Severity:** 🟠 High
- **Status:** passed
- **Description:** /env-demo.txt returned HTTP 404
- **Evidence:** `HTTP 404 for http://localhost:8081/env-demo.txt`

### ✅ ENV-001 — Demo config not accessible: /.env

- **Severity:** 🟠 High
- **Status:** passed
- **Description:** /.env returned HTTP 404
- **Evidence:** `HTTP 404 for http://localhost:8081/.env`

### ✅ ENV-001 — Demo config not accessible: /.env.demo

- **Severity:** 🟠 High
- **Status:** passed
- **Description:** /.env.demo returned HTTP 404
- **Evidence:** `HTTP 404 for http://localhost:8081/.env.demo`

### ✅ DBG-001 — Debug endpoint not accessible

- **Severity:** 🟠 High
- **Status:** passed
- **Description:** /debug returned HTTP 404
- **Evidence:** `HTTP 404 for http://localhost:8081/debug`

### ✅ DIR-001 — Directory listing not detected

- **Severity:** 🟡 Medium
- **Status:** passed
- **Description:** /static/ does not appear to expose a directory listing.
- **Evidence:** `HTTP 404 — no listing indicators found`

### ✅ PORT-001 — PostgreSQL port 5432 not exposed on host

- **Severity:** 🟠 High
- **Status:** passed
- **Description:** Port 5432 is not accessible from the host.
- **Evidence:** `TCP connection to localhost:5432 refused or timed out`

### ❌ HSTS-001 — HSTS header missing

- **Severity:** 🟡 Medium
- **Status:** failed
- **Description:** The Strict-Transport-Security header is not present.
- **Evidence:** `Header 'Strict-Transport-Security' not found in response from http://localhost:8081`
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

> **Note:** Compare with the `vulnerable` mode report to see which findings were resolved by the hardening measures applied.

## Limitations

- This is a local educational lab — not a production security audit.
- Checks are simplified and rule-based.
- This is not a penetration test.
- All credentials are fake/demo values.
- Results require manual validation before any action.
- Port checks only test localhost — not representative of network exposure.
