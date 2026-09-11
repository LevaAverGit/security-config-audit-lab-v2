# Interview Notes

Talking points for presenting this project in a Security Engineer / DevSecOps interview.
Junior-level framing: focused on configuration hardening and honest about scope.

---

## 30-second pitch

> I built a Docker-based security configuration lab that runs the same web stack twice —
> once intentionally misconfigured, once hardened — and a Python audit CLI that checks
> both, scores the risk, and produces a before/after report. The vulnerable stack scores
> 100/100 Critical; the hardened stack drops to Medium, where the only remaining findings
> are transport-layer controls (HSTS, HTTP→HTTPS redirect) that a plain-HTTP local lab
> can't satisfy. It demonstrates configuration review and hardening thinking, not a
> production audit.

---

## 60-second technical explanation

- **Two environments:** a `vulnerable/` Docker Compose stack (port 8080) and a
  `hardened/` stack (port 8081) running Nginx + Flask + PostgreSQL. Same application,
  different configuration — so the report shows exactly what hardening changes.
- **Audit CLI:** makes HTTP requests to the target and runs 13 independent rule-based
  checks — security headers, HSTS, HTTP→HTTPS redirect, server tokens, technology
  disclosure, debug endpoint, config-file exposure, directory listing, database port
  exposure, CORS policy, cookie flags, HTTP methods, and WAF presence.
- **Risk scoring:** each finding maps to a fixed severity weight; the total is capped at
  100. The score is deterministic and unit-tested, so the same target always scores the
  same way.
- **Reading the drop:** the vulnerable stack accumulates Critical/High findings to the
  100 cap; the hardened stack resolves every header, exposure, and network finding and
  lands at Medium, with the residual being transport-layer checks (HSTS, HTTP→HTTPS
  redirect) an HTTP-only lab can't satisfy. The delta is the value of the hardening work.
- **Why not production:** the check set is intentionally small and focused on common
  misconfiguration patterns, not comprehensive scanning — see the Limitations section in
  the README and `docs/RISK_MODEL.md`.

---

## What this project demonstrates

- Infrastructure security thinking — configuration as an attack surface
- Docker / Nginx awareness (server tokens, headers, port exposure)
- Knowledge of HTTP security headers and why each one matters
- Configuration review as a repeatable, scored process
- Risk-based reporting instead of a flat pass/fail
- Before/after comparison — the core deliverable of a hardening review
- Extensible check design (one function per check, independently testable)

---

## Files to show during interview

| Interview topic | File to show | What to explain |
|---|---|---|
| Check architecture | `audit/checks/` | One function per check, uniform signature, independently testable |
| Risk model | `docs/RISK_MODEL.md` | Severity weights, score cap, risk-level thresholds |
| Audit checklist | `docs/AUDIT_CHECKLIST.md` | What each check looks for and how to verify a fix |
| Vulnerable vs hardened | `reports/` | The before/after report — Critical (100/100) vs Medium |
| Tests | `tests/` | Every check mocked with `unittest.mock`; no Docker needed to test |

---

## Likely questions and short answers

1. **Why did you choose Docker / Nginx?**
   Docker gives a reproducible, isolated stack I can stand up and tear down. Nginx is a
   common real-world reverse proxy, so its misconfigurations are realistic to demonstrate.

2. **What is the vulnerable vs hardened idea?**
   Running the same app under two configurations isolates configuration as the only
   variable, so the report shows precisely what hardening changes and by how much.

3. **How does the risk score work?**
   Each failed or warning check adds a fixed weight by severity; the total is capped at
   100 and mapped to a risk level. It is deterministic and unit-tested.

4. **Why are security headers important?**
   They are browser-enforced defense in depth — CSP limits script sources, X-Frame-Options
   blocks clickjacking, HSTS forces HTTPS. Missing headers don't break the app, which is
   exactly why they get overlooked.

5. **How would you add a new check?**
   Add one module under `audit/checks/` following the existing signature, register it in
   the CLI, and add a mocked test. See `docs/CHECK_DEVELOPMENT_GUIDE.md`.

6. **What are the limitations?**
   Small, rule-based check set; HTTP-layer only; not a vulnerability scanner; tuned for the
   lab stacks, not arbitrary production targets.

7. **Is this a real audit tool?**
   No — it is an educational lab. A real audit needs scoping, authorization, broader
   coverage, and business-impact analysis per finding.

8. **How did you test it?**
   104 pytest tests. Each check patches `requests.get` via `unittest.mock` and covers
   all-missing, all-present, and network-error cases. No Docker required to run the suite.

9. **What would change in production?**
   Authorization and scoping first, then broader coverage (TLS config, auth flows),
   integration with a real scanner, and per-finding business-impact context.

10. **What task could you do in a real team based on this project?**
    Take a hardening checklist, automate the checks, run them against staging, and produce
    a before/after report that engineering and stakeholders can both read.

---

## Phrases to avoid

- "production audit"
- "enterprise-grade scanner"
- "full compliance audit"
- "replaces a professional pentest"
- "guarantees secure configuration"

---

## Good closing explanation

> This project shows I can compare an insecure configuration against a hardened one,
> automate the checks that distinguish them, score the risk, and explain the result to
> both engineers and stakeholders. It is a controlled lab for demonstrating that thinking,
> not a production audit tool.
