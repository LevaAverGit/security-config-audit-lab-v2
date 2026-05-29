# Infrastructure Security Audit Checklist

This checklist documents the checks performed by the audit CLI against a target web stack.
Each item maps to a concrete misconfiguration pattern found in real infrastructure audits.

## Scope

| Attribute | Value |
|---|---|
| Target stack | Nginx reverse proxy + Python web application + PostgreSQL |
| Deployment | Docker Compose (local lab) |
| Audit method | Automated HTTP checks + port scan |
| Out of scope | TLS/certificate inspection, authentication bypass, database query injection, host-level OS hardening |

---

## Checklist

### HTTP Security Headers

| Check ID | Check Name | Risk | Evidence Collected | Remediation | Verification |
|---|---|---|---|---|---|
| HDR-CSP | Content-Security-Policy | Medium — XSS mitigation absent | Presence/absence of `Content-Security-Policy` in response headers | Add `Content-Security-Policy: default-src 'self'` to Nginx config | `curl -I <target>` and inspect headers |
| HDR-XFO | X-Frame-Options | Medium — clickjacking possible | Presence/absence of `X-Frame-Options` | Add `X-Frame-Options: DENY` | `curl -I <target>` |
| HDR-XCTO | X-Content-Type-Options | Low — MIME sniffing possible | Presence/absence of `X-Content-Type-Options` | Add `X-Content-Type-Options: nosniff` | `curl -I <target>` |
| HDR-RP | Referrer-Policy | Low — information leakage via Referer | Presence/absence of `Referrer-Policy` | Add `Referrer-Policy: no-referrer` | `curl -I <target>` |
| HDR-PP | Permissions-Policy | Low — unneeded browser features accessible | Presence/absence of `Permissions-Policy` | Add `Permissions-Policy: geolocation=(), microphone=(), camera=()` | `curl -I <target>` |
| HDR-HSTS | Strict-Transport-Security | High — HTTP downgrade possible | Presence/absence of `Strict-Transport-Security` | Add HSTS header (requires HTTPS configured) | `curl -I <target>` |

### Server Information Disclosure

| Check ID | Check Name | Risk | Evidence Collected | Remediation | Verification |
|---|---|---|---|---|---|
| SRV-001 | Server version disclosure | Medium — aids fingerprinting and targeted CVE selection | `Server` header value | Set `server_tokens off;` in nginx.conf | `curl -I <target>` — Server header should not include version |

### Application Endpoint Exposure

| Check ID | Check Name | Risk | Evidence Collected | Remediation | Verification |
|---|---|---|---|---|---|
| DBG-001 | Debug endpoint accessible | High — may expose environment variables, credentials, internal state | HTTP status code + response body fragment of `/debug` | Disable debug route in application or block at reverse proxy | `curl http://<target>/debug` — should return 404 or 403 |
| ENV-001 | Demo/config file exposed | High — may expose configuration patterns, credentials | HTTP status code + response body fragment of `/static/env-demo.txt` | Block access to `.env`, `.txt`, `.cfg`, `.bak` files at Nginx; use `location ~* \.(env|txt|cfg|ini|bak)$ { return 404; }` | `curl http://<target>/static/env-demo.txt` — should return 404 |
| DIR-001 | Directory listing enabled | Low — reveals file structure, aids reconnaissance | HTTP response for `/static/` | Set `autoindex off;` in Nginx static location block | `curl http://<target>/static/` — should not return file listing |

### Network Exposure

| Check ID | Check Name | Risk | Evidence Collected | Remediation | Verification |
|---|---|---|---|---|---|
| NET-001 | Database port exposed on host | High — direct external access to database, enables brute-force and exploitation | TCP connection attempt to host:5432 | Remove `ports: "5432:5432"` from Docker Compose; database should communicate only on internal Docker network | `nmap -p 5432 <host>` or `nc -z <host> 5432` |

### CORS Policy

| Check ID | Check Name | Risk | Evidence Collected | Remediation | Verification |
|---|---|---|---|---|---|
| CORS-001 | Wildcard CORS origin | Medium — any origin can make credentialed requests if combined with `Access-Control-Allow-Credentials: true` | Value of `Access-Control-Allow-Origin` header | Restrict to specific trusted origins; never use `*` with `Allow-Credentials: true` | `curl -H "Origin: https://evil.example.com" -I <target>` |

---

## Mapping to Real Infrastructure Audit Work

The checks above correspond to items found in standard infrastructure security reviews:

| This Lab Check | Real-world Equivalent |
|---|---|
| HDR-CSP / HDR-XFO / HDR-XCTO | Web server hardening checklist — section "HTTP security headers" |
| HDR-HSTS | TLS/HTTPS configuration review — HTTP-to-HTTPS downgrade protection |
| SRV-001 | Server fingerprinting assessment — version disclosure via response headers |
| DBG-001 | Application security review — debug/diagnostic endpoint exposure |
| ENV-001 | Sensitive file exposure assessment — configuration and credential leakage |
| NET-001 | Network segmentation review — database access control, unnecessary port exposure |
| CORS-001 | Web application security review — cross-origin policy misconfiguration |

In a real infrastructure audit:
- Checks are performed against production or staging environments after scoping and authorization
- Each finding includes business impact assessment, not just technical severity
- Remediation is verified in a follow-up audit session
- The final report includes executive summary for non-technical stakeholders

This lab automates the technical evidence collection phase of such an audit against a controlled environment.

---

## Limitations

- Checks are rule-based and HTTP-level only; no OS-level hardening checks
- No TLS/certificate inspection (requires HTTPS endpoint)
- No authentication bypass or access control testing
- No static code analysis or SAST
- No dependency vulnerability scanning
- Mock environment — real infrastructure introduces additional complexity
- Manual review is required before acting on any finding in a production environment
