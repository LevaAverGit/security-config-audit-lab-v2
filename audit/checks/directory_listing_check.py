from __future__ import annotations

from typing import List

import requests

from audit.models import Finding

LISTING_INDICATORS = ["index of /", "parent directory", "directory listing"]


def check_directory_listing(target: str) -> List[Finding]:
    url = target.rstrip("/") + "/static/"
    try:
        resp = requests.get(url, timeout=5)
    except Exception as e:
        return [Finding(
            id="DIR-001",
            title="Directory listing check failed",
            severity="Medium",
            status="failed",
            description="Could not reach /static/ for directory listing check.",
            evidence=str(e),
            risk="Check incomplete.",
            recommendation="Ensure target is running.",
        )]

    body = resp.text.lower()
    listing_enabled = any(ind in body for ind in LISTING_INDICATORS)

    if listing_enabled:
        return [Finding(
            id="DIR-001",
            title="Directory listing enabled",
            severity="Medium",
            status="failed",
            description="The /static/ directory returns a directory index page.",
            evidence=f"HTTP {resp.status_code} — response contains directory listing indicators",
            risk="Directory listing reveals file structure and may expose unintended files.",
            recommendation="Set 'autoindex off' in nginx configuration.",
        )]

    return [Finding(
        id="DIR-001",
        title="Directory listing not detected",
        severity="Medium",
        status="passed",
        description="/static/ does not appear to expose a directory listing.",
        evidence=f"HTTP {resp.status_code} — no listing indicators found",
        risk="",
        recommendation="",
    )]
