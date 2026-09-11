# Extension Points

This document describes where the project is designed to be extended
and how to do so without modifying existing code.

---

## Adding a New HTTP Check

The check system uses a uniform interface. Adding a new check does not
require touching `models.py`, `scoring.py`, or `report_generator.py`.

**Steps:**
1. Create `audit/checks/newcheck.py` — implement `check_*(target: str) -> List[Finding]`
2. Register in `audit/cli.py`:
   ```python
   from audit.checks.newcheck import check_my_feature
   checks = [..., ("Label", lambda: check_my_feature(target))]
   ```
3. Write tests in `tests/test_newcheck.py`

See `docs/CHECK_DEVELOPMENT_GUIDE.md` for the full walkthrough.

---

## Adding a Network/Port Check

Port checks use raw TCP connections rather than HTTP. See `audit/checks/port_exposure_check.py`
for an example using `socket.create_connection()`.

```python
import socket

def check_redis_port(host: str) -> List[Finding]:
    try:
        with socket.create_connection((host, 6379), timeout=3):
            return [Finding(id="NET-002", ..., status="failed", ...)]
    except (ConnectionRefusedError, OSError):
        return [Finding(id="NET-002", ..., status="passed", ...)]
```

---

## Adding a New Report Format

Report generation is separated from the audit logic in `audit/report_generator.py`.
Both `generate_markdown_report()` and `generate_json_report()` accept an `AuditResult`
and return a string.

To add CSV or HTML output:
1. Add `generate_csv_report(result: AuditResult) -> str` in `report_generator.py`
2. Add `--csv FILE` argument to `audit/cli.py`
3. Call the new function and save with `save_report()`

---

## Adding a New Severity Level

Severity weights are defined in `audit/scoring.py`:

```python
SEVERITY_SCORES = {
    "Critical": 40,
    "High": 30,
    "Medium": 15,
    "Low": 5,
}
```

Add a new key (e.g., `"Info": 1`) and update the `REQUIRED_HEADERS` mapping
or check implementations that should use the new level.

---

## Adding Custom Check Configuration

Currently, thresholds are hardcoded in each check. To support a YAML config file
(like `config/default_rules.yml` in log-analyzer), you would:

1. Create `audit/config.py` with `load_config(path: str | None = None) -> dict`
2. Accept `--config FILE` in `audit/cli.py`
3. Pass `cfg` to check functions that need configurable thresholds:
   ```python
   def check_port_exposure(host: str, cfg: dict | None = None) -> List[Finding]:
       port = (cfg or {}).get("db_port", 5432)
       ...
   ```

---

## Adding a Docker Stack Variant

The `vulnerable/` and `hardened/` stacks are independent Docker Compose setups.
To add a new variant (e.g., a partially hardened intermediate stack):

1. Copy `vulnerable/` to `partial/`
2. Adjust `partial/nginx/default.conf` and `partial/app/app.py`
3. Expose on a different port (e.g., 8082)
4. Run audit with `--mode partial`

---

## Extending the Data Model

`audit/models.py` defines `Finding` and `AuditResult` as Python dataclasses.
To add a field:

```python
@dataclass
class Finding:
    ...
    cvss_score: float = 0.0  # new optional field
```

This is a non-breaking change for existing tests. Update `report_generator.py`
to include the new field in report output if needed.
