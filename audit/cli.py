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
from audit.report_generator import generate_markdown_report, generate_json_report, save_report
from audit.scoring import calculate_total_score, score_to_risk_level


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
    args = p.parse_args()

    result = run_audit(args.target, args.mode)

    report = generate_markdown_report(result)
    path = save_report(report, args.output)
    print(f"[+] Report saved: {path}", file=sys.stderr)

    if args.json:
        json_report = generate_json_report(result)
        json_path = save_report(json_report, args.json)
        print(f"[+] JSON report saved: {json_path}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
