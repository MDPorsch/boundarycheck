# Contributing

Thanks for looking. This is a security tool, so the bar for changes is deliberately high.

## Set up (about two minutes)

```bash
git clone --recurse-submodules https://github.com/MDPorsch/boundarycheck && cd boundarycheck
uv sync                      # Python 3.13 and the locked dependency set; the lab is installed editable, for development only
uv run pytest -q             # unit, negative, integration (against the lab) and packaging tests
uv run ruff check . && uv run ruff format --check . && uv run mypy
```

If you cloned without `--recurse-submodules`, run `git submodule update --init` (the `lab/` directory is empty otherwise).

## Rules that are not negotiable

1. **Tests first.** A change in behaviour starts with a failing test, and a security claim needs a test
   that would fail if the claim were false. Never skip or xfail a test to make a build green, and never
   write a test that passes on an empty tree.
2. **Do not weaken a guard** (loopback check, read-only methods, redirect refusal, size caps, redaction,
   the leak guard, file permissions) to make something easier. If you think one is wrong, open an issue first.
3. **Anything that changes auth, egress, token handling or report privacy needs an owner decision**: say
   so in the pull request.
4. **The oracle and comparator stay independent.** They import nothing that talks to a target
   (`tests/unit/test_independence.py` enforces it).
5. **Synthetic data only.** No real credentials, tokens, keys, names, addresses or customer data in code,
   tests, fixtures, issues or pull requests.
6. **Be honest in docs and reports.** Distinguish implemented from planned, and say what a result does not
   show. No badge before the workflow it points at has run.

## Mutation check (optional, slow)

`uv run python tools/mutation.py` injects known security bugs into a scratch copy and requires the suite
to catch every one. If you change code a mutant patches, "pattern not found" means the mutant is stale
and must be updated, not ignored. A new security property should come with a new mutant.

By contributing you agree your contribution is licensed under the Apache License 2.0.
