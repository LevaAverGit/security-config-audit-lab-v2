# Quality Assurance

## Test Strategy

All 104 tests run without Docker, without a live network target, and without
any external services. HTTP calls are intercepted by `unittest.mock.patch`.

```bash
python3 -m pytest tests/ -v
# or
make test
```

---

## Test Structure

Each check module has a dedicated test file:

| Test file | Module covered | What is tested |
|---|---|---|
| `test_headers_check.py` | `headers_check.py` | All 5 headers missing / present / partial / error |
| `test_hsts_check.py` | `hsts_check.py` | Missing / present / warning / error |
| `test_server_tokens_check.py` | `server_tokens_check.py` | Version in header / absent / error |
| `test_debug_check.py` | `debug_check.py` | 200 with keywords / 404 / 403 / error |
| `test_env_exposure_check.py` | `env_exposure_check.py` | Accessible / not accessible / error |
| `test_directory_listing_check.py` | `directory_listing_check.py` | Listing enabled / disabled / error |
| `test_port_exposure_check.py` | `port_exposure_check.py` | Port open / closed |
| `test_cors_check.py` | `cors_check.py` | Wildcard / specific origin / absent / warning |
| `test_cookie_security_check.py` | `cookie_security_check.py` | Missing flags / partial / all present / no cookie / error |
| `test_waf_check.py` | `waf_check.py` | Blocked (403/406) / not blocked (warning) / payload sent / error |
| `test_http_methods_check.py` | `http_methods_check.py` | Dangerous methods / safe methods / no Allow header / error |
| `test_https_redirect_check.py` | `https_redirect_check.py` | Redirect to HTTPS / no redirect / HTTP location / error |
| `test_technology_disclosure_check.py` | `technology_disclosure_check.py` | X-Powered-By present / absent / error |
| `test_cli_gating.py` | `cli.py` (`gating_exit_code`) | `--fail-on` thresholds / passed excluded / warning counted |
| `test_scoring.py` | `scoring.py` | Weights / capping / risk levels / summarize |
| `test_report_generator.py` | `report_generator.py` | Markdown structure / JSON structure / file save |

---

## Unit vs. Integration Tests

**Unit tests (all 104):** Mock `requests.get` and test each check function in isolation.
No network calls, no Docker, no filesystem side effects (except `test_report_generator.py`
which writes to a temp directory).

**Integration tests (not implemented):** End-to-end audit against a live stack.
These would require Docker and are intended as a manual verification step before
publishing reports. See `reports/` for example pre-run reports.

---

## Test Patterns

### HTTP check test pattern

```python
from unittest.mock import MagicMock, patch

def _mock_response(headers: dict, status: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.headers = headers
    return resp

def test_missing_header_returns_failed():
    with patch("audit.checks.headers_check.requests.get") as mock_get:
        mock_get.return_value = _mock_response({})
        findings = check_security_headers("http://localhost:8080")
    assert any(f.status == "failed" for f in findings)
```

### Error handling pattern

```python
def test_unreachable_target_returns_failed():
    with patch("audit.checks.debug_check.requests.get", side_effect=Exception("timeout")):
        findings = check_debug_endpoint("http://localhost:9999")
    assert findings[0].status == "failed"
    assert "timeout" in findings[0].evidence
```

---

## What Is Intentionally Not Tested

- **Full CLI execution** — `main()` in `audit/cli.py` is not unit-tested; the
  underlying check functions and report generators are tested independently
- **Docker stack behavior** — whether Nginx actually serves a specific header
  in the hardened config is verified manually against the live lab
- **Report file paths** — `save_report()` is tested with a temp path; the
  default `reports/` directory is not tested

---

## Manual Validation Checklist

Before publishing a new report to `reports/`:

- [ ] Vulnerable stack running on port 8080 — confirm `docker ps`
- [ ] Run full audit: `python3 -m audit.cli --target http://localhost:8080 --mode vulnerable --output reports/vulnerable_report.md --json reports/vulnerable_report.json`
- [ ] Hardened stack running on port 8081
- [ ] Run full audit for hardened
- [ ] Verify score in report matches expected (100 vulnerable, ~35 hardened — Medium; see docs/RISK_MODEL.md#score-examples)
- [ ] Review `reports/*.md` renders correctly in a Markdown viewer
- [ ] Commit updated reports with a `chore: update example reports` commit

---

## CI

GitHub Actions CI (`ci.yml`) runs on every push and pull request to `main`:
- Python 3.11
- Install dependencies from `requirements.txt`
- Run `python -m pytest tests/ -q`

Docker is not available in CI. All tests pass without it.
