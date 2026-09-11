# Architecture Decisions

This document records the key design choices and the reasoning behind them.

---

## Why Rule-Based Checks Instead of a Scanner Framework

**Decision:** Implement checks as standalone Python functions, not use a
scanner framework (Nikto, Nuclei, OWASP ZAP).

**Rationale:**
- A full scanner framework would obscure the underlying detection logic —
  the goal is to understand how checks work, not how to run a tool
- Rule-based logic is deterministic, fully testable without a live target,
  and easy to understand at the code level
- The check set is intentionally small and focused on common web server
  misconfiguration patterns, not comprehensive vulnerability scanning

**Trade-off:** Lower coverage than a full scanner. Accepted — the scope is
education and demonstrating the detection pipeline, not production auditing.

---

## Why a CLI Rather Than a Web UI

**Decision:** Expose the audit as a command-line tool, not a web service.

**Rationale:**
- Simpler deployment — no server process, no database, no authentication
- Output files (Markdown/JSON) are grep-friendly and easy to diff between runs
- CLI tools are composable with shell scripts, CI pipelines, and makefiles
- Easier to test — inputs and outputs are explicit

**Trade-off:** No interactive UI. A Streamlit dashboard could visualize
before/after results more clearly, but adds deployment complexity.

---

## Why Independent Check Modules

**Decision:** Each check is a separate module (`audit/checks/foo.py`) exporting
one function with a uniform signature: `def check_*(target: str) -> List[Finding]`.

**Rationale:**
- Each check can be tested in isolation without running the full audit
- New checks can be added without modifying any existing module
- The `cli.py` orchestrator only needs to call `check_*(target)` — it has no
  knowledge of check internals
- Uniform return type makes the aggregation loop trivial

**Trade-off:** Checks cannot easily share HTTP session state (e.g., re-use a
connection). Each check makes its own HTTP request to the target. Acceptable
for the current check count (13 checks, ~15 requests total).

---

## Why Dataclasses Instead of Pydantic

**Decision:** Use Python stdlib `dataclasses` for `Finding` and `AuditResult`.

**Rationale:**
- No additional dependencies for a simple data model
- Dataclasses are sufficient — no input validation from external sources is needed
  (all findings are constructed internally by check functions)
- Keeps the dependency list minimal (`requests` + `pytest` only)

**Trade-off:** No automatic serialization. `report_generator.py` manually accesses
dataclass fields. If the model grows significantly, Pydantic would be worth adding.

---

## Why Both Markdown and JSON Reports

**Decision:** Generate both `--output report.md` and `--json report.json` from the
same `AuditResult` object.

**Rationale:**
- Markdown is human-readable and renders in GitHub/GitLab
- JSON enables programmatic comparison between audit runs (`jq` for diffing)
- Both formats satisfy different audiences: a security engineer reads Markdown,
  a CI pipeline compares JSON

---

## Why Docker Compose for the Lab Stacks

**Decision:** Use Docker Compose rather than a remote staging environment or
mocked HTTP server.

**Rationale:**
- Reproducible and isolated — any contributor can run the exact same lab
- Demonstrates real Nginx and Flask behavior, not synthetic HTTP responses
- Two independent stacks (vulnerable/hardened) show the before/after
  configuration difference clearly
- No cloud resources or accounts required

**Trade-off:** Requires Docker to run the full demo. The test suite works without
Docker by design.

---

## Known Limitations

- Port exposure check uses `socket.create_connection()` — does not identify the
  service running on the port (just TCP reachability)
- No retry logic in HTTP checks — a single timeout marks a check as failed
- Check execution is sequential; a parallel check runner would reduce total
  audit time for larger check sets
- No authentication support — the audit is black-box and unauthenticated only
