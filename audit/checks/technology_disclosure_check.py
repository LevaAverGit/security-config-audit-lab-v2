from __future__ import annotations

from typing import List

import requests

from audit.models import Finding


def check_technology_disclosure(target: str) -> List[Finding]:
    try:
        resp = requests.get(target, timeout=5)
    except Exception as e:
        return [Finding(
            id="XPB-001",
            title="Target unreachable for technology disclosure check",
            severity="Medium",
            status="failed",
            description="Could not connect.",
            evidence=str(e),
            risk="Check incomplete.",
            recommendation="Ensure target is running.",
        )]

    powered_by = resp.headers.get("X-Powered-By", "")
    if powered_by:
        return [Finding(
            id="XPB-001",
            title="X-Powered-By header discloses technology stack",
            severity="Low",
            status="failed",
            description="The X-Powered-By header reveals backend framework or language information.",
            evidence=f"X-Powered-By: {powered_by}",
            risk="Technology stack disclosure aids fingerprinting and targeted exploitation.",
            recommendation="Remove the X-Powered-By header (e.g. 'app.disable(\"x-powered-by\")' in Express, or 'expose_php = Off' in php.ini).",
        )]

    return [Finding(
        id="XPB-001",
        title="X-Powered-By header absent",
        severity="Low",
        status="passed",
        description="No X-Powered-By header in response.",
        evidence="X-Powered-By header not present",
        risk="",
        recommendation="",
    )]
