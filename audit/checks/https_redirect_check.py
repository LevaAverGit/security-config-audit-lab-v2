from __future__ import annotations

from typing import List
from urllib.parse import urlparse, urlunparse

import requests

from audit.models import Finding

REDIRECT_STATUSES = (301, 302, 307, 308)


def check_https_redirect(target: str) -> List[Finding]:
    """Checks whether plain HTTP requests are redirected to HTTPS.

    Sends an HTTP request without following redirects and verifies the server
    responds with a redirect to an https:// location. Serving content over plain
    HTTP without forcing HTTPS exposes traffic to interception and SSL-stripping
    downgrade attacks.
    """
    parsed = urlparse(target)
    http_url = urlunparse(parsed._replace(scheme="http"))

    try:
        resp = requests.get(http_url, allow_redirects=False, timeout=5)
    except Exception as e:
        return [Finding(
            id="HTTPS-REDIRECT-001",
            title="HTTPS redirect check failed",
            severity="Medium",
            status="failed",
            description="Could not connect to target over HTTP.",
            evidence=str(e),
            risk="Check incomplete.",
            recommendation="Ensure the target is running and reachable over HTTP.",
        )]

    location = resp.headers.get("Location", "")
    if resp.status_code in REDIRECT_STATUSES and location.lower().startswith("https://"):
        return [Finding(
            id="HTTPS-REDIRECT-001",
            title="HTTP is redirected to HTTPS",
            severity="Low",
            status="passed",
            description=f"Plain HTTP request returned HTTP {resp.status_code} to an https:// location.",
            evidence=f"HTTP {resp.status_code} -> {location}",
            risk="",
            recommendation="",
        )]

    return [Finding(
        id="HTTPS-REDIRECT-001",
        title="HTTP is not redirected to HTTPS",
        severity="Medium",
        status="failed",
        description=f"Plain HTTP request returned HTTP {resp.status_code} without redirecting to HTTPS.",
        evidence=f"HTTP {resp.status_code}" + (f", Location: {location}" if location else ", no Location header"),
        risk="Traffic served over plain HTTP can be intercepted or modified (MITM) and is exposed to SSL-stripping downgrade attacks.",
        recommendation="Configure the web server to 301-redirect all HTTP traffic to HTTPS, and pair it with HSTS.",
    )]
