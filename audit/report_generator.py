from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import List

from audit.models import AuditResult, Finding
from audit.scoring import calculate_total_score, score_to_risk_level, summarize_by_severity

SEV_ICON = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
STATUS_ICON = {"failed": "❌", "passed": "✅", "warning": "⚠️"}

BEFORE_AFTER_TABLE = """
| Check | Vulnerable | Hardened |
|---|---|---|
| Security headers | ❌ Missing | ✅ Present |
| Debug endpoint `/debug` | ❌ Exposed, leaks env vars | ✅ Returns 404 |
| Demo config `/static/env-demo.txt` | ❌ Publicly accessible | ✅ Blocked (404) |
| PostgreSQL port 5432 | ❌ Exposed on host | ✅ Internal only |
| Directory listing `/static/` | ❌ Enabled | ✅ Disabled |
| Server version disclosure | ❌ May expose nginx version | ✅ server_tokens off |
"""

LIMITATIONS = [
    "This is a local educational lab — not a production security audit.",
    "Checks are simplified and rule-based.",
    "This is not a penetration test.",
    "All credentials are fake/demo values.",
    "Results require manual validation before any action.",
    "Port checks only test localhost — not representative of network exposure.",
]


def generate_markdown_report(result: AuditResult) -> str:
    score = calculate_total_score(result.findings)
    risk_level = score_to_risk_level(score)
    sev_summary = summarize_by_severity(result.findings)
    failed = result.failed()
    passed = result.passed()

    lines: List[str] = []
    lines.append("# Security Config Audit Report\n")

    lines.append("## Target\n")
    lines.append(f"- **URL:** {result.target}")
    lines.append(f"- **Mode:** {result.mode}")
    lines.append(f"- **Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    lines.append("## Executive Summary\n")
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    lines.append(f"| Total checks run | {len(result.findings)} |")
    lines.append(f"| Failed / Warning | {len(failed)} |")
    lines.append(f"| Passed | {len(passed)} |")
    lines.append(f"| Risk score | {score}/100 |")
    lines.append(f"| Risk level | {risk_level} |")
    for sev in ("Critical", "High", "Medium", "Low"):
        cnt = sev_summary.get(sev, 0)
        if cnt:
            lines.append(f"| {SEV_ICON.get(sev, '')} {sev} findings | {cnt} |")
    lines.append("")

    lines.append("## Findings\n")
    if not result.findings:
        lines.append("_No findings._\n")
    else:
        for f in result.findings:
            icon = STATUS_ICON.get(f.status, "")
            sev_icon = SEV_ICON.get(f.severity, "")
            lines.append(f"### {icon} {f.id} — {f.title}\n")
            lines.append(f"- **Severity:** {sev_icon} {f.severity}")
            lines.append(f"- **Status:** {f.status}")
            lines.append(f"- **Description:** {f.description}")
            lines.append(f"- **Evidence:** `{f.evidence}`")
            if f.risk:
                lines.append(f"- **Risk:** {f.risk}")
            if f.recommendation:
                lines.append(f"- **Recommendation:** {f.recommendation}")
            lines.append("")

    lines.append("## Before/After Comparison\n")
    lines.append(BEFORE_AFTER_TABLE)

    if result.mode == "vulnerable":
        lines.append(
            "> **Note:** Findings in this report represent **intentionally misconfigured** settings "
            "in a local educational lab. Run `hardened` mode to see the improved state.\n"
        )
    else:
        lines.append(
            "> **Note:** Compare with the `vulnerable` mode report to see which findings were resolved "
            "by the hardening measures applied.\n"
        )

    lines.append("## Limitations\n")
    for lim in LIMITATIONS:
        lines.append(f"- {lim}")
    lines.append("")

    return "\n".join(lines)


def generate_json_report(result: AuditResult) -> str:
    score = calculate_total_score(result.findings)
    data = {
        "generated_at": datetime.now().isoformat(),
        "target": result.target,
        "mode": result.mode,
        "summary": {
            "total_checks": len(result.findings),
            "failed": len(result.failed()),
            "passed": len(result.passed()),
            "risk_score": score,
            "risk_level": score_to_risk_level(score),
            "by_severity": summarize_by_severity(result.findings),
        },
        "findings": [
            {
                "id": f.id, "title": f.title, "severity": f.severity,
                "status": f.status, "description": f.description,
                "evidence": f.evidence, "risk": f.risk,
                "recommendation": f.recommendation,
            }
            for f in result.findings
        ],
        "limitations": LIMITATIONS,
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


def save_report(content: str, output_path: str) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path
