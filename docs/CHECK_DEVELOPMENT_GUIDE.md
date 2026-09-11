# Check Development Guide

This guide walks through implementing a new audit check from scratch.

---

## Anatomy of a Check Module

Every check module in `audit/checks/` follows this pattern:

```python
from __future__ import annotations
from typing import List
import requests
from audit.models import Finding


def check_my_feature(target: str) -> List[Finding]:
    """One-line description of what this check does."""
    url = target.rstrip("/") + "/some/path"
    try:
        resp = requests.get(url, timeout=5)
    except Exception as e:
        return [Finding(
            id="XYZ-001",
            title="Check failed — target unreachable",
            severity="High",      # match the severity of the check being skipped
            status="failed",
            description="Could not reach target.",
            evidence=str(e),
            risk="Check incomplete.",
            recommendation="Ensure the target is running.",
        )]

    # Evaluate the response
    if <condition_is_safe>:
        return [Finding(
            id="XYZ-001",
            title="Feature not exposed",
            severity="High",
            status="passed",
            description="Description of what was checked.",
            evidence=f"HTTP {resp.status_code} for {url}",
            risk="",
            recommendation="",
        )]

    return [Finding(
        id="XYZ-001",
        title="Feature exposed",
        severity="High",
        status="failed",
        description="Description of the problem found.",
        evidence=f"HTTP {resp.status_code}; <relevant detail>",
        risk="Description of the risk if exploited.",
        recommendation="Specific remediation step.",
    )]
```

---

## Finding Fields

| Field | Type | Required | Notes |
|---|---|---|---|
| `id` | str | Yes | Unique check ID, e.g. `HDR-001`, `DBG-001` |
| `title` | str | Yes | Short human-readable name |
| `severity` | str | Yes | `Critical` / `High` / `Medium` / `Low` |
| `status` | str | Yes | `failed` / `passed` / `warning` |
| `description` | str | Yes | One sentence describing the finding |
| `evidence` | str | Yes | What the scanner observed (URL, status code, header value) |
| `risk` | str | For failed | Risk if not remediated |
| `recommendation` | str | For failed | Specific remediation action |

`risk` and `recommendation` should be empty strings (`""`) for `passed` findings.

---

## Severity Guide

| Severity | Use when |
|---|---|
| High (30 pts) | Direct path to credential exposure, data leakage, or service compromise |
| Medium (15 pts) | Requires additional conditions or user interaction to exploit |
| Low (5 pts) | Defense-in-depth control; rarely the primary attack vector |

---

## Registering the Check

In `audit/cli.py`, add to the `checks` list:

```python
from audit.checks.mycheck import check_my_feature

checks = [
    ...
    ("My feature name", lambda: check_my_feature(target)),
]
```

Each entry is a `(label, callable)` pair; the CLI loop invokes the callable so
the per-check progress line prints as the check actually runs. The string label
is used only for progress output to stderr.

---

## Writing Tests

Create `tests/test_mycheck.py`:

```python
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from audit.checks.mycheck import check_my_feature


def _mock_response(status: int, body: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.text = body
    return resp


def test_safe_condition_returns_passed():
    with patch("audit.checks.mycheck.requests.get") as mock_get:
        mock_get.return_value = _mock_response(404)
        findings = check_my_feature("http://localhost:8080")
    assert len(findings) == 1
    assert findings[0].status == "passed"


def test_exposed_condition_returns_failed():
    with patch("audit.checks.mycheck.requests.get") as mock_get:
        mock_get.return_value = _mock_response(200, "sensitive content")
        findings = check_my_feature("http://localhost:8080")
    assert findings[0].status == "failed"
    assert findings[0].severity == "High"
    assert "sensitive" in findings[0].evidence.lower()  # evidence is populated


def test_unreachable_target_returns_failed():
    with patch("audit.checks.mycheck.requests.get", side_effect=Exception("timeout")):
        findings = check_my_feature("http://localhost:9999")
    assert findings[0].status == "failed"
    assert "timeout" in findings[0].evidence
```

Minimum test coverage per check:
- `passed` scenario
- `failed` scenario (with evidence content assertion)
- Network error / unreachable target

---

## Documenting the Check

Add a row to `docs/AUDIT_CHECKLIST.md` with:
- Check ID, name, severity, evidence collected, remediation, verification command

Add the check to the example mapping table in `docs/AUDIT_REPORT_EXAMPLE.md`.

---

## Check Development Checklist

- [ ] Module in `audit/checks/mycheck.py`
- [ ] Function returns `List[Finding]`
- [ ] Handles network errors gracefully
- [ ] Finding IDs are unique and consistent
- [ ] Registered in `audit/cli.py`
- [ ] Test file with passed/failed/error scenarios
- [ ] Entry in `docs/AUDIT_CHECKLIST.md`
