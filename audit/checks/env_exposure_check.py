from __future__ import annotations

from typing import List

import requests

from audit.models import Finding

SENSITIVE_PATHS = [
    "/static/env-demo.txt",
    "/env-demo.txt",
    "/.env",
    "/.env.demo",
]

SENSITIVE_KEYWORDS = [
    "demo-secret", "demo-token", "password", "api_token", "secret_key",
]


def check_env_exposure(target: str) -> List[Finding]:
    findings: List[Finding] = []
    base = target.rstrip("/")

    for path in SENSITIVE_PATHS:
        url = base + path
        try:
            resp = requests.get(url, timeout=5)
        except Exception:
            continue

        if resp.status_code == 200:
            body = resp.text.lower()
            has_sensitive = any(kw in body for kw in SENSITIVE_KEYWORDS)
            findings.append(Finding(
                id="ENV-001",
                title=f"Demo config file accessible: {path}",
                severity="High" if has_sensitive else "Medium",
                status="failed",
                description=f"A configuration/demo file is publicly accessible at {url}",
                evidence=f"HTTP {resp.status_code} — {'contains sensitive-looking demo values' if has_sensitive else 'file accessible'}",
                risk="Exposed demo configs reveal patterns used in real configs and may expose secrets if misconfigured.",
                recommendation="Remove or restrict access to config/env files. Block via nginx location rule.",
            ))
        else:
            findings.append(Finding(
                id="ENV-001",
                title=f"Demo config not accessible: {path}",
                severity="High",
                status="passed",
                description=f"{path} returned HTTP {resp.status_code}",
                evidence=f"HTTP {resp.status_code} for {url}",
                risk="",
                recommendation="",
            ))

    return findings
