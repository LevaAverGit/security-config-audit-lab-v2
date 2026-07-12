# WAF layer — ModSecurity + OWASP Core Rule Set

This lab includes an optional Web Application Firewall stack that places
[ModSecurity](https://github.com/owasp-modsecurity/ModSecurity) with the
[OWASP Core Rule Set](https://coreruleset.org/) in front of the vulnerable app.
It demonstrates defence-in-depth: even when the application itself is
misconfigured, the WAF blocks common exploit attempts before they reach it.

## Run it

```bash
docker compose -f waf/docker-compose.yml up --build
```

- The CRS-nginx proxy listens on **http://localhost:8082** and forwards clean
  traffic to the app.
- Malicious requests that trip the CRS are rejected with **HTTP 403** before the
  app ever sees them.

## Expected behaviour

```bash
# Clean request — passes through to the app
$ curl -s -o /dev/null -w "%{http_code}\n" "http://localhost:8082/health"
200

# XSS / SQLi payload — blocked by the OWASP CRS
$ curl -s -o /dev/null -w "%{http_code}\n" \
    "http://localhost:8082/?q=<script>alert(1)</script>' OR '1'='1"
403
```

## Confirm it with the audit tool

The audit CLI includes a `WAF presence` check (`audit/checks/waf_check.py`) that
sends an attack payload and inspects the response code:

```bash
# Against the app with no WAF (port 8080) — warns that no WAF is present
$ python -m audit.cli --target http://localhost:8080 --mode vulnerable
    [WAF presence] 1 checks, 1 failed        # "No WAF detected"

# Against the WAF-protected proxy (port 8082) — the attack is blocked
$ python -m audit.cli --target http://localhost:8082 --mode hardened
    [WAF presence] 1 checks, 0 failed        # "WAF blocked a malicious request"
```

## Tuning

The CRS paranoia level and anomaly thresholds are set in
[`waf/docker-compose.yml`](../waf/docker-compose.yml):

- `PARANOIA` / `BLOCKING_PARANOIA` — 1 (fewer false positives) … 4 (strictest)
- `ANOMALY_INBOUND` / `ANOMALY_OUTBOUND` — score thresholds at which a request is blocked

Raise the paranoia level to catch more attacks at the cost of more false
positives; lower it for noisy production traffic.
