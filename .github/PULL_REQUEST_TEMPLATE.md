## What and why

## Checklist
- [ ] A failing test came first (or this is docs only), and the suite passes: `uv run pytest -q`
- [ ] `ruff check`, `ruff format --check` and `mypy` are clean
- [ ] No guard was weakened (loopback check, read-only methods, redirect refusal, caps, redaction, leak guard, file permissions), or the PR explains exactly why
- [ ] Anything touching auth, egress, token handling or report privacy is called out here for an owner decision
- [ ] A new security property comes with a new mutant in `tools/mutation.py`
- [ ] Synthetic data only; docs say what is implemented and what is not
