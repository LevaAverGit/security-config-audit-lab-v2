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
| High | 30 | HSTS missing, debug endpoint exposed, config file exposed, database port on host |
| Medium | 15 | CSP missing, X-Frame-Options missing, CORS wildcard, server version disclosed |
| Low | 5 | X-Content-Type-Options, Referrer-Policy, Permissions-Policy, directory listing |

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

### Vulnerable stack (10 fails, 0 warnings)

| Check | Severity | Points |
|---|---|---|
| HDR-HSTS | High | 30 |
| DBG-001 | High | 30 |
| ENV-001 | High | 30 |
| NET-001 | High | 30 |
| HDR-CSP | Medium | 15 |
| HDR-XFO | Medium | 15 |
| CORS-001 | Medium | 15 |
| SRV-001 | Medium | 15 |
| HDR-XCTO | Low | 5 |
| HDR-RP | Low | 5 |
| HDR-PP | Low | 5 |
| DIR-001 | Low | 5 |

Sum = 200 → capped → **Risk score: 100 / 100** — Risk level: Critical

### Hardened stack (0 fails, 2 warnings)

| Check | Result | Points |
|---|---|---|
| HDR-HSTS | Warning (no HTTPS in lab) | 30 |
| CORS-001 | Warning (noted) | 15 |

Sum = 45 → **Risk score: 45 / 100** — Risk level: Medium

The hardened stack still scores Medium rather than Low because two warnings remain.
The HSTS warning reflects a genuine environment constraint (no HTTPS in the lab),
not a resolved finding. In a production environment with HTTPS, this would pass.

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
- **NET-001** — Database reachable on host port enables direct brute-force or exploitation.
- **HDR-HSTS** — Without HTTPS enforcement, traffic can be intercepted or downgraded.

### Medium severity (15 pts)

Findings that require additional conditions or user interaction to exploit:

- **HDR-CSP** — Without Content-Security-Policy, XSS attacks are easier to exploit.
  Impact depends on whether XSS vectors exist in the application.
- **HDR-XFO** — Clickjacking requires a crafted attacker page and user interaction.
- **CORS-001** — Wildcard CORS only becomes critical when combined with
  `Allow-Credentials: true`; alone it limits cross-origin data access.
- **SRV-001** — Version disclosure aids targeted exploitation but is not exploitable alone.

### Low severity (5 pts)

Defense-in-depth controls that reduce attack surface but are rarely the primary attack vector:

- **HDR-XCTO** — MIME sniffing attacks are browser-dependent and usually require serving
  attacker-controlled content.
- **HDR-RP** — Referrer leakage is an information disclosure issue, not a direct exploit path.
- **HDR-PP** — Restricts browser feature access; impact depends on application functionality.
- **DIR-001** — Reveals file structure but does not directly expose file contents.

---

## Limitations

- The model assigns uniform weights per severity. In a real assessment, weights would be
  adjusted for the specific application's threat model (e.g., HSTS matters more for a
  financial service than for an internal tool).
- No compensating control detection — a WAF or CDN upstream may mitigate some findings.
  The model scores what is observable at the HTTP layer.
- Score comparison between targets is only meaningful if the same checks are run.
  Adding or removing checks changes the maximum achievable score.
