from __future__ import annotations

from typing import List

import requests

from audit.models import Finding

REQUIRED_FLAGS = ("Secure", "HttpOnly", "SameSite")


def check_cookie_security(target: str) -> List[Finding]:
    """Checks that any cookie the target sets carries Secure, HttpOnly, and SameSite."""
    try:
        resp = requests.get(target, timeout=5)
    except Exception as e:
        return [Finding(
            id="COOKIE-001",
            title="Target unreachable for cookie check",
            severity="Medium",
            status="failed",
            description="Could not connect to target.",
            evidence=str(e),
            risk="Check incomplete.",
            recommendation="Ensure target is running.",
        )]

    set_cookie = resp.headers.get("Set-Cookie", "")

    if not set_cookie:
        return [Finding(
            id="COOKIE-001",
            title="No cookies set by the response",
            severity="Low",
            status="passed",
            description="The response does not set any cookies, so no cookie flags are required.",
            evidence="Set-Cookie header not present in response",
            risk="",
            recommendation="",
        )]

    lowered = set_cookie.lower()
    missing = [flag for flag in REQUIRED_FLAGS if flag.lower() not in lowered]

    if missing:
        return [Finding(
            id="COOKIE-001",
            title=f"Cookie missing security flags: {', '.join(missing)}",
            severity="Medium",
            status="failed",
            description="A cookie is set without one or more of the Secure, HttpOnly, and SameSite attributes.",
            evidence=f"Set-Cookie: {set_cookie}",
            risk=(
                "Missing HttpOnly exposes the cookie to theft via XSS; missing Secure allows "
                "it to travel over plain HTTP; missing SameSite enables CSRF."
            ),
            recommendation="Set 'Secure; HttpOnly; SameSite=Strict' on session cookies.",
        )]

    return [Finding(
        id="COOKIE-001",
        title="Cookie sets Secure, HttpOnly, and SameSite",
        severity="Low",
        status="passed",
        description="The cookie includes the Secure, HttpOnly, and SameSite attributes.",
        evidence=f"Set-Cookie: {set_cookie}",
        risk="",
        recommendation="",
    )]
