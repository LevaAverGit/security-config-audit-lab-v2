.PHONY: test lint install clean help

help:
	@echo "Available targets:"
	@echo "  install  — create venv and install dependencies"
	@echo "  test     — run pytest (no Docker required)"
	@echo "  lint     — run ruff linter"
	@echo "  clean    — remove __pycache__ and .pytest_cache"

install:
	python3 -m venv .venv
	.venv/bin/pip install -r requirements.txt

test:
	python3 -m pytest tests/ -q

lint:
	python3 -m ruff check audit/ tests/ || true

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache
