# Risk Model

This document describes the risk scoring model used by the audit CLI to calculate
a numeric risk score and assign a risk level to a target stack.

All values in this document match the implementation in `audit/scoring.py`.

---

## Severity Weights

Each check result with status `failed` or `warning` contributes a fixed point
value to the overall risk score based on severity.

| Severity | Points | Examples |
|---|---|---|
| Critical | 40 | Reserved for auth bypass, RCE exposure (not used in current checks) |
| High | 30 | debug endpoint exposed, config file exposed, database port on host |
| Medium | 15 | CSP missing, X-Frame-Options missing, HSTS missing, CORS wildcard, directory listing |
| Low | 5 | X-Content-Type-Options, Referrer-Policy, Permissions-Policy, server/stack version disclosed |

Both `failed` and `warning` findings count at full weight. A `warning` result indicates
a finding that is expected or accepted in the current environment (e.g., HSTS on an
HTTP-only lab) — it still contributes to the score so it remains visible in the report.

---

## Score Calculation

```
risk_score = sum(severity_weight for each finding with status "failed" or "warning")
```

The raw score is capped at **100** for display purposes.

Implementation: `audit/scoring.py` → `calculate_total_score()`.

---

## Score Examples

### Vulnerable stack (worst case — every check fails)

| Check | Severity | Points |
|---|---|---|
| DBG-001 | High | 30 |
| ENV-001 | High | 30 |
| PORT-001 | High | 30 |
| HDR-CSP | Medium | 15 |
| HDR-XFO | Medium | 15 |
| CORS-001 | Medium | 15 |
| HSTS-001 | Medium | 15 |
| DIR-001 | Medium | 15 |
| HDR-XCTO | Low | 5 |
| HDR-RP | Low | 5 |
| HDR-PP | Low | 5 |
| SRV-001 | Low | 5 |

Sum = 185 → capped → **Risk score: 100 / 100** — Risk level: Critical

### Hardened stack (2 fails, 1 warning)

| Check | Result | Points |
|---|---|---|
| HSTS-001 | Failed — no HTTPS to enforce in the lab | 15 |
| HTTPS-REDIRECT-001 | Failed — HTTP-only lab has no HTTPS to redirect to | 15 |
| WAF-001 | Warning — no WAF in the default hardened stack | 5 |

Sum = 35 → **Risk score: 35 / 100** — Risk level: Medium

The hardened stack lands in Medium rather than Low because of transport-layer
controls the lab cannot satisfy: it serves plain HTTP, so HSTS and the HTTP→HTTPS
redirect structurally fail regardless of hardening, and the optional WAF is a
separate stack (`waf/`). In production with TLS terminated and the WAF in front,
these resolve and the score drops into the Low band.

---

## Risk Level Thresholds

| Score range | Risk Level |
|---|---|
| 0 – 20 | Low |
| 21 – 50 | Medium |
| 51 – 90 | High |
| 91 – 100 | Critical |

Implementation: `audit/scoring.py` → `score_to_risk_level()`.

---

## Severity Assignment Rationale

### High severity (30 pts)

These findings have a direct, near-immediate path to impact without requiring chaining
with other vulnerabilities:

- **DBG-001** — Debug endpoint leaks credentials and secrets in a single HTTP request.
- **ENV-001** — Static config file directly exposes connection strings and tokens.
- **PORT-001** — Database reachable on host port enables direct brute-force or exploitation.

### Medium severity (15 pts)

Findings that require additional conditions or user interaction to exploit:

- **HDR-CSP** — Without Content-Security-Policy, XSS attacks are easier to exploit.
  Impact depends on whether XSS vectors exist in the application.
- **HDR-XFO** — Clickjacking requires a crafted attacker page and user interaction.
- **CORS-001** — Wildcard CORS only becomes critical when combined with
  `Allow-Credentials: true`; alone it limits cross-origin data access.
- **HSTS-001 / HTTPS-REDIRECT-001** — Downgrade and SSL-strip attacks require an active
  MITM position, so transport-layer gaps rate below direct-exposure findings.
- **DIR-001** — Reveals file structure and can surface unintended files, but does not by
  itself dump file contents.
- **COOKIE-001** — Missing cookie flags enable XSS theft / CSRF only in combination with
  another vector.

### Low severity (5 pts)

Defense-in-depth controls that reduce attack surface but are rarely the primary attack vector:

- **HDR-XCTO** — MIME sniffing attacks are browser-dependent and usually require serving
  attacker-controlled content.
- **HDR-RP** — Referrer leakage is an information disclosure issue, not a direct exploit path.
- **HDR-PP** — Restricts browser feature access; impact depends on application functionality.
- **SRV-001 / XPB-001** — Version and stack disclosure aid targeted exploitation but are
  not exploitable alone.
- **WAF-001** — Informational: the absence of a WAF removes a defence-in-depth layer rather
  than being a vulnerability itself (scored as a warning).

---

## Limitations

- The model assigns uniform weights per severity. In a real assessment, weights would be
  adjusted for the specific application's threat model (e.g., HSTS matters more for a
  financial service than for an internal tool).
- No compensating control detection — a WAF or CDN upstream may mitigate some findings.
  The model scores what is observable at the HTTP layer.
- Score comparison between targets is only meaningful if the same checks are run.
  Adding or removing checks changes the maximum achievable score.
