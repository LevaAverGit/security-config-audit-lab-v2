#!/usr/bin/env python3
"""Security Config Audit Lab — audit runner."""

import argparse
import sys
from urllib.parse import urlparse

from audit.models import AuditResult
from audit.checks.headers_check import check_security_headers
from audit.checks.server_tokens_check import check_server_tokens
from audit.checks.env_exposure_check import check_env_exposure
from audit.checks.debug_check import check_debug_endpoint
from audit.checks.directory_listing_check import check_directory_listing
from audit.checks.port_exposure_check import check_port_exposure
from audit.checks.hsts_check import check_hsts
from audit.checks.cors_check import check_cors
from audit.checks.cookie_security_check import check_cookie_security
from audit.checks.waf_check import check_waf
from audit.checks.http_methods_check import check_http_methods
from audit.checks.https_redirect_check import check_https_redirect
from audit.checks.technology_disclosure_check import check_technology_disclosure
from audit.report_generator import generate_markdown_report, generate_json_report, save_report
from audit.scoring import calculate_total_score, score_to_risk_level

_SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def gating_exit_code(findings, fail_on: str) -> int:
    """Return 1 if any failed/warning finding is at or above the fail_on severity, else 0.

    Lets the audit gate a CI pipeline (e.g. `--fail-on high`). fail_on="none" disables gating.
    """
    if fail_on == "none":
        return 0
    threshold = _SEVERITY_ORDER[fail_on]
    worst = max(
        (_SEVERITY_ORDER.get(f.severity.lower(), 0)
         for f in findings if f.status in ("failed", "warning")),
        default=0,
    )
    return 1 if worst >= threshold else 0


def run_audit(target: str, mode: str) -> AuditResult:
    result = AuditResult(target=target, mode=mode)
    host = urlparse(target).hostname or "localhost"

    print(f"[*] Auditing {target} (mode: {mode})", file=sys.stderr)

    checks = [
        ("Security headers", check_security_headers(target)),
        ("Server tokens", check_server_tokens(target)),
        ("Env file exposure", check_env_exposure(target)),
        ("Debug endpoint", check_debug_endpoint(target)),
        ("Directory listing", check_directory_listing(target)),
        ("Port exposure", check_port_exposure(host)),
        ("HSTS", check_hsts(target)),
        ("CORS policy", check_cors(target)),
        ("Cookie security", check_cookie_security(target)),
        ("WAF presence", check_waf(target)),
        ("HTTP methods", check_http_methods(target)),
        ("HTTPS redirect", check_https_redirect(target)),
        ("Technology disclosure", check_technology_disclosure(target)),
    ]

    for name, findings in checks:
        result.findings.extend(findings)
        failed_count = sum(1 for f in findings if f.status in ("failed", "warning"))
        print(f"    [{name}] {len(findings)} checks, {failed_count} failed", file=sys.stderr)

    score = calculate_total_score(result.findings)
    risk = score_to_risk_level(score)
    print(f"[+] Score: {score} — Risk level: {risk}", file=sys.stderr)
    return result


def main() -> int:
    p = argparse.ArgumentParser(description="Security Config Audit Lab")
    p.add_argument("--target", required=True, help="Target URL, e.g. http://localhost:8080")
    p.add_argument("--mode", choices=["vulnerable", "hardened"], default="vulnerable")
    p.add_argument("--output", default="reports/audit_report.md", help="Output .md file")
    p.add_argument("--json", metavar="FILE", help="Also save JSON report to this path")
    p.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        default="none",
        help="Exit non-zero if a failed finding at or above this severity exists (CI gating).",
    )
    args = p.parse_args()

    result = run_audit(args.target, args.mode)

    report = generate_markdown_report(result)
    path = save_report(report, args.output)
    print(f"[+] Report saved: {path}", file=sys.stderr)

    if args.json:
        json_report = generate_json_report(result)
        json_path = save_report(json_report, args.json)
        print(f"[+] JSON report saved: {json_path}", file=sys.stderr)

    code = gating_exit_code(result.findings, args.fail_on)
    if code:
        print(f"[!] Findings at or above '{args.fail_on}' severity — failing for CI gating.", file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
