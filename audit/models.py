from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass
class Finding:
    id: str
    title: str
    severity: str       # Critical / High / Medium / Low
    status: str         # failed / passed / warning
    description: str
    evidence: str
    risk: str
    recommendation: str


@dataclass
class AuditResult:
    target: str
    mode: str
    findings: List[Finding] = field(default_factory=list)

    def failed(self) -> List[Finding]:
        return [f for f in self.findings if f.status in ("failed", "warning")]

    def passed(self) -> List[Finding]:
        return [f for f in self.findings if f.status == "passed"]
