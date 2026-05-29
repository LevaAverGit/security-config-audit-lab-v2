# Contributing

## Local Setup

```bash
git clone https://github.com/LevaAverGit/security-config-audit-lab.git
cd security-config-audit-lab

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

No additional dependencies are required. Docker is only needed to run the actual
lab stacks (not for tests).

## Running Tests

```bash
python3 -m pytest tests/ -v
# or
make test
```

Tests run without Docker. All HTTP calls are mocked via `unittest.mock`.

## Running the Lab (requires Docker)

```bash
# Vulnerable stack
cd vulnerable && docker compose up -d --build && cd ..
python3 -m audit.cli --target http://localhost:8080 --mode vulnerable --output reports/vulnerable_report.md

# Hardened stack
cd hardened && docker compose up -d --build && cd ..
python3 -m audit.cli --target http://localhost:8081 --mode hardened --output reports/hardened_report.md
```

See `docs/CLI_USAGE.md` for full CLI reference.

## Code Style

- Python 3.11+, type hints on all public functions
- `ruff` for linting — run `make lint` (if configured) or `ruff check audit/ tests/`
- One function per check, uniform return type `List[Finding]`
- No bare `except:` — always catch specific exceptions

## Adding a New Audit Check

1. Create `audit/checks/mycheck.py` following the pattern in existing checks
2. Export one function: `def check_*(target: str) -> List[Finding]`
3. Add to the `checks` list in `audit/cli.py`
4. Write `tests/test_mycheck.py` — mock `requests.get`, cover passed/failed/error cases
5. Document the check in `docs/AUDIT_CHECKLIST.md`

See `docs/CHECK_DEVELOPMENT_GUIDE.md` for the complete walkthrough.

## Branch and Commit Convention

- Branch: `feature/<short-name>`, `fix/<short-name>`, `docs/<short-name>`
- Commit messages: imperative present tense — `Add TLS version check`, `Fix CORS evidence field`
- Keep commits focused — one logical change per commit

## Limitations

- Docker is not available in the CI environment for this project — tests use mocks only
- The check set is intentionally small; real security scanners (Nikto, Nuclei) cover orders of magnitude more surface area
- No rate limiting, retries, or proxy support in the current CLI
