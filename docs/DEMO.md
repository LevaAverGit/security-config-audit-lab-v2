# Demo — proof of run

## 1. Audit against a live target

The CLI makes real HTTP requests to a target, runs the checks, and scores the
result. Below is a live run against a plain HTTP server (no security headers),
which the audit correctly flags as high risk:

```text
$ python -m audit.cli --target http://127.0.0.1:8099 --mode vulnerable --output report.md

[*] Auditing http://127.0.0.1:8099 (mode: vulnerable)
    [Security headers] 5 checks, 5 failed
    [Server tokens] 1 checks, 1 failed
    [Env file exposure] 4 checks, 0 failed
    [Debug endpoint] 1 checks, 0 failed
    [Directory listing] 1 checks, 0 failed
    [Port exposure] 1 checks, 1 failed
    [HSTS] 1 checks, 1 failed
    [CORS policy] 1 checks, 0 failed
[+] Score: 95 — Risk level: Critical
[+] Report saved: report.md
```

## 2. Before / after hardening

Running the same audit against the two Docker stacks shipped in this repo shows
the whole point of the lab — the risk score collapsing once the hardening is
applied:

| Target | Risk score | Risk level | Report |
|---|---|---|---|
| Vulnerable stack (port 8080) | **100/100** | 🔴 Critical | [reports/vulnerable_report.md](../reports/vulnerable_report.md) |
| Hardened stack (port 8081) | **15/100** | 🟢 Low | [reports/hardened_report.md](../reports/hardened_report.md) |

The delta is driven by the hardened Nginx adding the security headers
(CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, HSTS),
suppressing `Server` version tokens, blocking `.env`/config exposure, disabling
the debug route, and not publishing the database port to the host.

## Reproduce

```bash
# Against the Docker labs
cd vulnerable && docker compose up -d && cd ..
python -m audit.cli --target http://localhost:8080 --mode vulnerable --output reports/vulnerable_report.md

cd hardened && docker compose up -d && cd ..
python -m audit.cli --target http://localhost:8081 --mode hardened --output reports/hardened_report.md

# Or against any URL you control
python -m audit.cli --target https://example.com --output report.md --json report.json
```
