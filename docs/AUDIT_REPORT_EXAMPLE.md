# Security Configuration Audit — Example Report Structure

This document illustrates the structure of a security configuration audit report
as produced by this lab. The format follows the pattern used in real infrastructure
security assessments: executive summary, scoped findings with evidence, risk ratings,
and remediation guidance.

The actual reports from lab runs are in [`reports/`](../reports/).

---

## Executive Summary

**Audit target:** Local Docker Compose web stack (Nginx + Flask + PostgreSQL)  
**Audit date:** 2026-05-24  
**Scope:** HTTP endpoint security, server configuration, network exposure  
**Method:** Automated rule-based checks via Python audit CLI  

| Metric | Vulnerable stack | Hardened stack |
|---|---|---|
| Total checks | 15 | 15 |
| Failed / Warning | 10 | 1 |
| Risk score | 100 / 100 | 45 / 100 |
| Risk level | Critical | Medium |

**Summary:** The vulnerable stack exhibits a combination of high-severity findings across
server configuration, application endpoint exposure, and network architecture. The hardened
stack addresses all critical and high-severity items. One medium-severity residual finding
(CORS wildcard) remains in the hardened stack as an informational note.

---

## Scope

| Attribute | Detail |
|---|---|
| In scope | HTTP response headers, server version disclosure, debug endpoint, static file exposure, database port exposure, directory listing, HSTS, CORS policy |
| Out of scope | TLS certificate validity, authentication logic, SQL injection, XSS, host OS hardening, dependency CVE scanning |
| Authorization | Lab environment — no production systems involved |
| Methodology | Black-box HTTP checks; no credentials provided to the scanner |

---

## Key Findings Summary

| ID | Finding | Severity | Status (vulnerable) | Status (hardened) |
|---|---|---|---|---|
| HDR-CSP | Missing Content-Security-Policy | Medium | ❌ Failed | ✅ Passed |
| HDR-XFO | Missing X-Frame-Options | Medium | ❌ Failed | ✅ Passed |
| HDR-XCTO | Missing X-Content-Type-Options | Low | ❌ Failed | ✅ Passed |
| HDR-RP | Missing Referrer-Policy | Low | ❌ Failed | ✅ Passed |
| HDR-PP | Missing Permissions-Policy | Low | ❌ Failed | ✅ Passed |
| HDR-HSTS | Missing Strict-Transport-Security | High | ❌ Failed | ⚠️ Warning (no HTTPS in lab) |
| SRV-001 | Server version disclosed | Medium | ❌ Failed | ✅ Passed |
| DBG-001 | Debug endpoint accessible | High | ❌ Failed | ✅ Passed |
| ENV-001 | Config file exposed | High | ❌ Failed | ✅ Passed |
| NET-001 | Database port on host | High | ❌ Failed | ✅ Passed |
| DIR-001 | Directory listing | Low | ❌ Failed | ✅ Passed |
| CORS-001 | CORS wildcard origin | Medium | ❌ Failed | ⚠️ Warning |

---

## Detailed Findings

### Finding: DBG-001 — Debug Endpoint Accessible

**Severity:** High  
**Status:** Failed (vulnerable) / Passed (hardened)

**Description:**  
The application exposes a `/debug` endpoint that returns environment variables and
internal configuration when accessed over HTTP without authentication. This endpoint
is present in the application code as a diagnostic aid but was not disabled before
deployment.

**Evidence (vulnerable stack):**
```
GET http://localhost:8080/debug → HTTP 200
Response body contains: FLASK_ENV, DB_HOST, DB_USER, SECRET_KEY (values visible)
```

**Impact:**  
An attacker who discovers this endpoint can enumerate:
- Database host and credentials
- Application secret keys
- Internal service hostnames
- Environment configuration

This finding alone can enable full application compromise depending on what is exposed.

**Remediation:**  
Option A (preferred): Remove the debug route from application code entirely.  
Option B: Add Nginx location block to return 404 for `/debug`:
```nginx
location = /debug {
    return 404;
}
```

**Verification:**  
After remediation: `curl http://<target>/debug` must return 404 or 403.
Confirm no environment variable names or values are present in the response.

---

### Finding: NET-001 — Database Port Exposed on Host

**Severity:** High  
**Status:** Failed (vulnerable) / Passed (hardened)

**Description:**  
The PostgreSQL service in the vulnerable stack publishes port 5432 to the host network
(`0.0.0.0:5432:5432` in Docker Compose). This makes the database directly accessible
from outside the container network.

**Evidence (vulnerable stack):**
```
TCP connection to localhost:5432 — success
PostgreSQL banner received
```

**Impact:**  
Direct database access enables:
- Credential brute-force against PostgreSQL
- Direct SQL execution if credentials are obtained or weak
- Enumeration of database structure and data

In cloud or multi-tenant environments this is a critical finding.

**Remediation:**  
Remove the `ports` mapping for the database service in Docker Compose.
The application connects to the database via the internal Docker network by service name
(`db:5432`), not via the host.

```yaml
# vulnerable — remove this:
ports:
  - "5432:5432"

# hardened — no ports section for db service
```

**Verification:**  
`nc -z localhost 5432` or `nmap -p 5432 localhost` must show port closed/filtered.

---

## Remediation Plan

| Priority | Finding | Owner | Effort | Verification |
|---|---|---|---|---|
| P1 — Immediate | DBG-001, ENV-001, NET-001 | Infrastructure / DevOps | Low (config change) | Automated check re-run |
| P2 — High | HDR-HSTS | Infrastructure | Medium (requires HTTPS) | Automated check + manual |
| P3 — Medium | HDR-CSP, HDR-XFO, SRV-001, CORS-001 | Infrastructure | Low (Nginx config) | Automated check re-run |
| P4 — Low | HDR-XCTO, HDR-RP, HDR-PP, DIR-001 | Infrastructure | Low (Nginx config) | Automated check re-run |

---

## Limitations

- **Scope:** HTTP-level checks only; host OS hardening, application logic, and authentication are not covered.
- **Method:** Rule-based detection — no exploit attempts, no fuzzing, no authenticated scanning.
- **Environment:** Lab environment (Docker on localhost); real infrastructure may have additional controls (WAF, load balancers, CDN) that affect findings.
- **False positives:** A finding of "missing header" does not guarantee exploitability — other controls may compensate.
- **False negatives:** This scan does not find all vulnerabilities. Manual review and additional tooling are required for a complete assessment.
- **Not a penetration test:** No exploitation of found vulnerabilities was performed.
