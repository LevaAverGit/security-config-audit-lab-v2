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

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | Audit completed successfully (regardless of findings) |
| Non-zero | Unhandled exception — check stderr for details |

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

## Expected Output (stderr)

```
[*] Auditing http://localhost:8080 (mode: vulnerable)
    [Security headers] 5 checks, 5 failed
    [Server tokens] 1 checks, 1 failed
    [Env file exposure] 1 checks, 1 failed
    [Debug endpoint] 1 checks, 1 failed
    [Directory listing] 1 checks, 1 failed
    [Port exposure] 1 checks, 1 failed
    [HSTS] 1 checks, 1 failed
    [CORS policy] 1 checks, 1 failed
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
  "target": "http://localhost:8080",
  "mode": "vulnerable",
  "score": 100,
  "risk_level": "Critical",
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
  ]
}
```

The JSON report is suitable for diff-based comparison between audit runs,
or for ingestion into external tooling.
