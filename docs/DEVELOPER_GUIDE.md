# Developer Guide

## Repository Structure

```
security-config-audit-lab/
├── audit/                     # Audit CLI package
│   ├── cli.py                 # Entry point — orchestrates checks, output
│   ├── models.py              # Finding, AuditResult dataclasses
│   ├── scoring.py             # Severity weights, risk level calculation
│   ├── report_generator.py    # Markdown + JSON serialisation
│   └── checks/                # 13 check modules, one per file
│       ├── headers_check.py   # Security headers (CSP, XFO, XCTO, RP, PP)
│       ├── hsts_check.py      # Strict-Transport-Security
│       ├── https_redirect_check.py
│       ├── server_tokens_check.py
│       ├── technology_disclosure_check.py  # X-Powered-By
│       ├── debug_check.py     # /debug endpoint exposure
│       ├── env_exposure_check.py
│       ├── directory_listing_check.py
│       ├── port_exposure_check.py  # TCP port scan
│       ├── cors_check.py
│       ├── cookie_security_check.py
│       ├── http_methods_check.py
│       └── waf_check.py       # WAF presence probe
├── tests/                     # pytest tests (no Docker required)
├── vulnerable/                # Intentionally misconfigured Docker stack
│   ├── docker-compose.yml
│   ├── nginx/default.conf
│   └── app/                   # Flask app with /debug and exposed static file
├── hardened/                  # Hardened Docker stack
│   ├── docker-compose.yml
│   ├── nginx/default.conf
│   └── app/
├── docs/                      # Documentation
├── reports/                   # Pre-generated example reports
├── requirements.txt
├── requirements-dev.txt       # + ruff linter
├── pyproject.toml             # ruff and pytest config
├── Makefile
└── CONTRIBUTING.md
```

---

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt    # includes ruff
```

---

## Common Commands

```bash
make test            # run pytest
make lint            # ruff check (non-blocking, shows issues)
make install         # create venv + install deps
make clean           # remove __pycache__ and .pytest_cache

# Run audit against vulnerable lab (requires Docker)
make test                                            # no Docker needed
cd vulnerable && docker compose up -d --build && cd ..
python3 -m audit.cli --target http://localhost:8080 --mode vulnerable --output reports/vulnerable_report.md
```

---

## Adding a New Check

See `docs/CHECK_DEVELOPMENT_GUIDE.md` for the complete walkthrough.

Short version:
1. `audit/checks/newcheck.py` → implement `check_*(target: str) -> List[Finding]`
2. Register in `audit/cli.py`
3. `tests/test_newcheck.py` → passed/failed/error cases

---

## Debugging

Run a single check in isolation:

```python
from audit.checks.debug_check import check_debug_endpoint
findings = check_debug_endpoint("http://localhost:8080")
for f in findings:
    print(f.id, f.status, f.evidence)
```

Run a specific test with verbose output:

```bash
python3 -m pytest tests/test_debug_check.py -v
```

Inspect the full audit result without writing a report:

```python
from audit.cli import run_audit
result = run_audit("http://localhost:8080", "vulnerable")
print(result.findings)
```

---

## Module Relationships

```
cli.py
  ↓ imports
  ├── checks/*.py       → returns List[Finding]
  ├── models.py         → Finding, AuditResult
  ├── scoring.py        → calculate_total_score, score_to_risk_level
  └── report_generator.py → generate_markdown_report, generate_json_report
```

`scoring.py` and `report_generator.py` depend only on `models.py`.
Check modules depend only on `models.py` and `requests`.
This keeps the dependency graph flat and test isolation easy.
