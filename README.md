# Security Config Audit Lab

[![CI](https://github.com/LevaAverGit/security-config-audit-lab-v2/actions/workflows/ci.yml/badge.svg)](https://github.com/LevaAverGit/security-config-audit-lab-v2/actions/workflows/ci.yml)

Local Docker-based security lab for comparing vulnerable and hardened web infrastructure configurations. The project includes Docker Compose environments, a Python audit CLI, rule-based misconfiguration checks, risk scoring, before/after comparison, and Markdown/JSON reports.

**Quick look:** see [docs/DEMO.md](docs/DEMO.md) for a captured audit run — the risk score drops from **100/100 (Critical)** on the vulnerable stack to **15/100 (Low)** on the hardened one.

## Overview

The lab runs two independent Docker Compose stacks:

- **Vulnerable stack** (port 8080) — intentionally misconfigured Nginx + Flask + PostgreSQL. Exposes debug endpoints, demo config files, server version, and database port on the host.
- **Hardened stack** (port 8081) — the same stack with security controls applied: security headers, disabled debug route, blocked config file, no port exposure, server token suppressed.

The **audit CLI** makes HTTP requests to the target, runs rule-based checks, computes a risk score capped at 100, and writes Markdown and JSON reports.

## Engineering Highlights

- **Pluggable check architecture** — each check is an independent module in `audit/checks/` returning a typed `Finding` list; adding a new check requires no changes to existing code
- **Typed data model** — `Finding` and `AuditResult` dataclasses with explicit severity/status fields; no stringly-typed result handling
- **Deterministic scoring** — `scoring.py` maps severity to fixed weights with a hard cap; score is reproducible and unit-tested
- **Zero live-infrastructure tests** — all 92 tests use `unittest.mock` to patch HTTP responses; Docker is never required to run the test suite
- **Dual report format** — same `AuditResult` object serialised to both Markdown (human readable) and JSON (machine readable / downstream tooling)
- **Structured CLI** — `argparse`-based CLI with `--target`, `--mode`, `--output`, `--json` flags; exit codes reflect pass/fail

## Check Architecture

```
audit/cli.py              ← entry point, orchestrates checks
audit/models.py           ← Finding, AuditResult dataclasses
audit/scoring.py          ← severity weights, risk level thresholds
audit/report_generator.py ← Markdown + JSON serialisation
audit/checks/
    headers_check.py      ← CSP, XFO, XCTO, RP, PP (5 findings)
    hsts_check.py         ← Strict-Transport-Security
    server_tokens_check.py← Server header version disclosure
    debug_check.py        ← /debug endpoint exposure
    env_exposure_check.py ← static config file exposure
    directory_listing_check.py ← autoindex detection
    port_exposure_check.py← TCP port scan for DB port
    cors_check.py         ← CORS wildcard origin
    cookie_security_check.py ← Set-Cookie Secure/HttpOnly/SameSite flags
    waf_check.py          ← WAF presence probe (attack payload → 403)
    http_methods_check.py ← dangerous HTTP methods (TRACE/PUT/DELETE) via OPTIONS
    https_redirect_check.py ← HTTP-to-HTTPS redirect enforcement
```

Each check module exports exactly one function with signature:
```python
def check_*(target: str) -> List[Finding]:
```
This uniform interface makes checks independently testable and trivially composable.

## WAF Layer (optional)

Beyond configuration auditing, the repo ships an optional **Web Application
Firewall** stack — ModSecurity with the OWASP Core Rule Set — in front of the
vulnerable app, plus a `WAF presence` audit check that verifies it:

```bash
docker compose -f waf/docker-compose.yml up --build
# Attack payloads are blocked with HTTP 403 before reaching the app.
```

See [docs/WAF.md](docs/WAF.md) for the full walkthrough and expected output.

## How to Add a New Audit Check

1. Create `audit/checks/newcheck.py` following the pattern in any existing check
2. Import and add to the `checks` list in `audit/cli.py`
3. Add a test file `tests/test_newcheck.py` — see `docs/CHECK_DEVELOPMENT_GUIDE.md`

See `docs/CHECK_DEVELOPMENT_GUIDE.md` for the full walkthrough.

## Problem

Common web/infrastructure misconfigurations are easy to overlook but straightforward to detect automatically:

- Missing security headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- Exposed debug endpoints that leak environment variables
- Exposed demo config/env files accessible over HTTP
- Database port exposed on the host network
- Server version disclosure via `Server` header
- Directory listing enabled on static paths

## Solution

```
Docker lab → HTTP checks → findings → risk score → Markdown/JSON reports → before/after comparison
```

## Features

- Vulnerable Docker Compose stack (port 8080)
- Hardened Docker Compose stack (port 8081)
- Nginx reverse proxy configuration
- Flask demo application with intentional misconfigurations
- PostgreSQL service
- Security headers check (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- Server tokens / version disclosure check
- Demo config file exposure check
- Debug endpoint check
- Directory listing check
- PostgreSQL port exposure check
- HSTS header check
- CORS policy check (wildcard origin detection)
- Cookie security check (Secure / HttpOnly / SameSite flags)
- WAF presence check (attack payload blocked with 403/406)
- HTTP methods check (flags TRACE / PUT / DELETE via OPTIONS)
- HTTPS redirect check (verifies plain HTTP is 301-redirected to HTTPS)
- Optional ModSecurity + OWASP CRS WAF stack (`waf/`, see [docs/WAF.md](docs/WAF.md))
- Risk scoring capped at 100/100
- Markdown and JSON reports
- Pytest coverage — all check modules covered by unit tests using mocks (no Docker required)

## Project Structure

```
security-config-audit-lab/
├── vulnerable/                 # Misconfigured Docker stack (port 8080)
│   ├── docker-compose.yml
│   ├── nginx/default.conf
│   ├── app/                    # Flask app with /debug endpoint and exposed static file
│   └── db/init.sql
├── hardened/                   # Hardened Docker stack (port 8081)
│   ├── docker-compose.yml
│   ├── nginx/default.conf
│   ├── app/                    # Flask app, /debug disabled, static file blocked
│   └── db/init.sql
├── audit/                      # Audit CLI and checks
│   ├── cli.py                  # CLI entry point
│   ├── models.py
│   ├── scoring.py
│   ├── report_generator.py
│   └── checks/
│       ├── headers_check.py
│       ├── server_tokens_check.py
│       ├── env_exposure_check.py
│       ├── debug_check.py
│       ├── directory_listing_check.py
│       ├── port_exposure_check.py
│       ├── hsts_check.py
│       └── cors_check.py
├── reports/                    # Live audit reports
├── tests/                      # pytest tests (no Docker required)
├── requirements.txt
└── LICENSE
```

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run Vulnerable Lab

```bash
cd vulnerable
docker compose up -d --build
cd ..

# Verify endpoints
curl -i http://localhost:8080/
curl -i http://localhost:8080/debug
curl -i http://localhost:8080/static/env-demo.txt

# Run audit
python3 -m audit.cli \
  --target http://localhost:8080 \
  --mode vulnerable \
  --output reports/vulnerable_report.md \
  --json reports/vulnerable_report.json

cd vulnerable
docker compose down
```

## Run Hardened Lab

```bash
cd hardened
docker compose up -d --build
cd ..

# Verify endpoints
curl -i http://localhost:8081/
curl -i http://localhost:8081/debug
curl -i http://localhost:8081/static/env-demo.txt

# Run audit
python3 -m audit.cli \
  --target http://localhost:8081 \
  --mode hardened \
  --output reports/hardened_report.md \
  --json reports/hardened_report.json

cd hardened
docker compose down
```

## Example Results

**Vulnerable stack:**
- Risk score: 100/100
- Risk level: Critical

**Hardened stack:**
- Risk score: 15/100
- Risk level: Low

## Before/After Comparison

| Check | Vulnerable | Hardened |
|---|---|---|
| Security headers | Missing | Present |
| Debug endpoint `/debug` | Exposed, leaks env vars | Disabled (404) |
| Demo config `/static/env-demo.txt` | Accessible | Not accessible (404) |
| PostgreSQL port 5432 | Exposed on host | Internal only |
| Directory listing `/static/` | Enabled / checked | Not detected |
| Server version | nginx version exposed | Version not disclosed |

## Reports

Live reports from a full audit run are included:

- `reports/vulnerable_report.md` / `reports/vulnerable_report.json`
- `reports/hardened_report.md` / `reports/hardened_report.json`

## Documentation

| Document | Description |
|---|---|
| [`docs/AUDIT_CHECKLIST.md`](docs/AUDIT_CHECKLIST.md) | Full checklist of checks with severity, evidence collected, remediation, and verification steps |
| [`docs/RISK_MODEL.md`](docs/RISK_MODEL.md) | Risk scoring model: severity weights, score calculation, thresholds, rationale |
| [`docs/AUDIT_REPORT_EXAMPLE.md`](docs/AUDIT_REPORT_EXAMPLE.md) | Example audit report showing executive summary, findings, and remediation plan |
| [`docs/CHECK_DEVELOPMENT_GUIDE.md`](docs/CHECK_DEVELOPMENT_GUIDE.md) | How to implement and test a new audit check |
| [`docs/CLI_USAGE.md`](docs/CLI_USAGE.md) | CLI arguments, output format, and usage examples |
| [`docs/EXTENSION_POINTS.md`](docs/EXTENSION_POINTS.md) | Extending checks, report formats, and severity rules |
| [`docs/ARCHITECTURE_DECISIONS.md`](docs/ARCHITECTURE_DECISIONS.md) | Why the architecture was designed this way |
| [`docs/QUALITY_ASSURANCE.md`](docs/QUALITY_ASSURANCE.md) | Test strategy, what is tested, and what is not |
| [`docs/INTERVIEW_NOTES.md`](docs/INTERVIEW_NOTES.md) | Pitch, talking points, likely questions, and scope for interviews |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Local setup, running tests, adding checks, commit conventions |

## Testing Strategy

```bash
python3 -m pytest tests/ -v
# or with make:
make test
```

**92 tests passing.** Tests do not require Docker or a running network target.

Every check module has a dedicated test file. Each test patches `requests.get` via
`unittest.mock` and covers:
- All headers missing → expected `failed` findings
- All headers present → expected `passed` findings
- Network error → graceful `failed` finding with error evidence
- Severity and check ID fields match the spec

`audit/scoring.py` has its own test file covering weight mapping, score capping,
warning inclusion, and threshold boundaries.

See `docs/QUALITY_ASSURANCE.md` for the full test strategy.

## Scoring

| Severity | Points |
|---|---|
| Critical | 40 |
| High | 30 |
| Medium | 15 |
| Low | 5 |

Both `failed` and `warning` results count at full weight. Total score capped at 100.

Risk levels: 0–20 Low, 21–50 Medium, 51–90 High, 91–100 Critical.

See [`docs/RISK_MODEL.md`](docs/RISK_MODEL.md) for full rationale and threshold derivation.

## Limitations

- Local educational lab — not a production audit
- Simplified rule-based checks, not a vulnerability scanner replacement
- Not a penetration test
- Fake/demo credentials only — no real secrets
- Manual validation is required before acting on any finding

## How This Maps to Real Security Audit Work

Infrastructure security audits follow a structured methodology: scope definition,
evidence collection, finding classification, risk scoring, remediation guidance,
and verification. This lab automates the evidence collection and classification
phase against a controlled environment.

| This lab | Real audit equivalent |
|---|---|
| Rule-based HTTP checks | Automated web server hardening checklist |
| Risk score (0–100) | Finding severity classification and prioritization |
| Vulnerable vs. hardened comparison | Baseline vs. remediated state assessment |
| Before/after report | Audit follow-up verification report |
| `docs/AUDIT_CHECKLIST.md` | Audit scope and check mapping document |
| `docs/RISK_MODEL.md` | Risk methodology and scoring criteria |
| `docs/AUDIT_REPORT_EXAMPLE.md` | Finding report template used by security teams |

In a production infrastructure audit:
- Checks run against production or staging after explicit scoping and authorization
- Each finding includes business impact assessment alongside technical severity
- Remediation is re-verified in a follow-up session
- The report includes an executive summary for non-technical stakeholders

This lab demonstrates the technical evidence collection logic for that workflow.

## What This Project Demonstrates for Security Roles

- Translating an infrastructure hardening checklist into automated checks
- Severity classification: distinguishing high-impact findings (debug endpoint,
  exposed DB port) from defense-in-depth controls (header policy)
- Risk scoring: aggregating findings into a single comparable metric
- Before/after security state comparison — the core deliverable of a hardening review
- Structured report generation suitable for engineering and stakeholder audiences
- pytest design for HTTP-check modules without requiring live infrastructure (mocked responses)
- Docker Compose as an isolated, reproducible lab environment

## Related Projects

| Project | Focus | What connects them |
|---|---|---|
| [mini-siem-detection-lab](https://github.com/LevaAverGit/mini-siem-detection-lab) | SOC / detection engineering | Detects misconfigurations and security events in logs; complements hardening |
| [appsec-review-lab](https://github.com/LevaAverGit/appsec-review-lab) | AppSec / OWASP | Security Config Audit Lab covers server-layer hardening; AppSec Lab covers application-layer vulnerabilities |
| [pd-scanner-152fz](https://github.com/LevaAverGit/pd-scanner-152fz) | Compliance automation | Server hardening is a prerequisite for 152-FZ infrastructure compliance |

---

## License

MIT — see [LICENSE](LICENSE).
