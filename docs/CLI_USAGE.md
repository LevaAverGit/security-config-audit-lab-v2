# CLI Usage

## Invocation

```bash
python3 -m audit.cli --target <URL> [options]
```

## Arguments

| Argument | Required | Default | Description |
|---|---|---|---|
| `--target URL` | Yes | — | Target URL, e.g. `http://localhost:8080` |
| `--mode MODE` | No | `vulnerable` | Label for the report: `vulnerable` or `hardened` |
| `--output FILE` | No | `reports/audit_report.md` | Path for the Markdown report |
| `--json FILE` | No | — | Also save a JSON report to this path |
| `--fail-on SEV` | No | `none` | Exit non-zero if a failed/warning finding at or above `SEV` exists (`critical`/`high`/`medium`/`low`/`none`). For CI gating. |

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | Audit ran; no finding met the `--fail-on` threshold (always 0 when `--fail-on none`, the default) |
| 1 | A failed/warning finding at or above the `--fail-on` severity was found (CI gating) |

## Examples

### Audit the vulnerable lab stack

```bash
cd vulnerable && docker compose up -d --build && cd ..

python3 -m audit.cli \
  --target http://localhost:8080 \
  --mode vulnerable \
  --output reports/vulnerable_report.md \
  --json reports/vulnerable_report.json
```

### Audit the hardened lab stack

```bash
cd hardened && docker compose up -d --build && cd ..

python3 -m audit.cli \
  --target http://localhost:8081 \
  --mode hardened \
  --output reports/hardened_report.md \
  --json reports/hardened_report.json
```

### Audit any HTTP target (outside the lab)

```bash
python3 -m audit.cli \
  --target http://my-dev-server:8080 \
  --mode vulnerable \
  --output reports/dev_audit.md
```

### Gate a CI pipeline on findings

```bash
# Exit 1 if any High or Critical finding is present, so the job fails the build.
python3 -m audit.cli \
  --target http://localhost:8080 \
  --output reports/audit.md \
  --fail-on high
```

## Expected Output (stderr)

```
[*] Auditing http://localhost:8080 (mode: vulnerable)
    [Security headers] 5 checks, 5 failed
    [Server tokens] 1 checks, 1 failed
    [Env file exposure] 4 checks, 1 failed
    [Debug endpoint] 1 checks, 1 failed
    [Directory listing] 1 checks, 0 failed
    [Port exposure] 1 checks, 1 failed
    [HSTS] 1 checks, 1 failed
    [CORS policy] 1 checks, 0 failed
    [Cookie security] 1 checks, 1 failed
    [WAF presence] 1 checks, 1 failed
    [HTTP methods] 1 checks, 0 failed
    [HTTPS redirect] 1 checks, 1 failed
    [Technology disclosure] 1 checks, 0 failed
[+] Score: 100 — Risk level: Critical
[+] Report saved: reports/vulnerable_report.md
```

## Markdown Report Structure

The generated Markdown report contains:
- Audit target and mode
- Summary table: total checks, failed, score, risk level
- Per-finding table with ID, severity, status, description
- Findings detail section for all failed/warning items
- Remediation guidance per finding

## JSON Report Structure

```json
{
  "generated_at": "2026-05-24T17:41:19.000000",
  "target": "http://localhost:8080",
  "mode": "vulnerable",
  "summary": {
    "total_checks": 20,
    "failed": 13,
    "passed": 7,
    "risk_score": 100,
    "risk_level": "Critical",
    "by_severity": {"High": 3, "Medium": 5, "Low": 5}
  },
  "findings": [
    {
      "id": "HDR-CSP",
      "title": "Missing header: Content-Security-Policy",
      "severity": "Medium",
      "status": "failed",
      "description": "...",
      "evidence": "...",
      "risk": "...",
      "recommendation": "..."
    }
  ],
  "limitations": ["..."]
}
```

The JSON report is suitable for diff-based comparison between audit runs,
or for ingestion into external tooling.
