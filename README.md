# boundarycheck

[![CI](https://github.com/MDPorsch/boundarycheck/actions/workflows/ci.yml/badge.svg)](https://github.com/MDPorsch/boundarycheck/actions/workflows/ci.yml)
[![CodeQL](https://github.com/MDPorsch/boundarycheck/actions/workflows/codeql.yml/badge.svg)](https://github.com/MDPorsch/boundarycheck/actions/workflows/codeql.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Check that an API enforces the authorization boundaries **you declare**: tenant isolation, roles,
hidden objects and field exposure. You write down who is allowed to see what (the *policy*); the tool
replays read-only requests as each test user and compares what the API actually did with what your
policy says it should do. Every result is one of seven honest states, and a failed or partial run can
never look clean.

> **Status: v0.1.0, alpha.** Live targets are **loopback-only and read-only** (`GET`/`HEAD`): it tests the
> API you run on your own machine. Write checks exist only against the built-in in-process lab. Use it
> only against systems you own or are explicitly authorized to assess. See [SECURITY.md](SECURITY.md)
> and [LIMITATIONS.md](LIMITATIONS.md).

## What it does, and what it does not

| It checks | It does **not** |
|---|---|
| Cross-tenant reads (BOLA): can user A read tenant B's object? | Test writes on a **live** target: it sends `GET`/`HEAD` only, so a write-path flaw there is **not detected** |
| Role limits on read routes (BFLA): can a viewer reach an admin route? | Decide whether your policy is *right*: it judges the API against the policy you give it |
| Hidden objects: does a forbidden object answer exactly like a missing one? | Prove an API is secure: `no_issue_observed` means one request matched the policy, nothing more |
| Field exposure: does a response carry a field that role should not see? | Test timing channels, concurrency, rate limits or anything it was not told about |
| List routes: does a list name objects the user may not see, or count them in `total`? | Reach a remote host (planned for v0.2: a scoped, HTTPS-only, allow-listed design) |
| Refused writes (fixture only): does a request the policy says must be refused still **change a row**, whatever status it returns? | Send a write the policy allows: that would test functionality, and it would change state |

## Install

```bash
pipx install boundarycheck          # once release 0.1.0 is on PyPI (see below)
```

PyPI publication goes through a protected release workflow that needs the owner's approval
([docs/releasing.md](docs/releasing.md)); until <https://pypi.org/project/boundarycheck/> shows 0.1.0,
install from source as in the next section. A wheel install validates configs, plans, and runs
`--transport live` against loopback; the `fixture` transport and the examples need a source checkout.

## Try it in two minutes (no network, no credentials)

The demo target is the [tenant-boundary-lab](https://github.com/MDPorsch/tenant-boundary-lab): a small
multi-tenant API with a *patched* and a *deliberately vulnerable* variant, served in process.

```bash
git clone --recurse-submodules https://github.com/MDPorsch/boundarycheck
cd boundarycheck
uv sync                                   # needs uv (https://docs.astral.sh/uv/) and Python 3.13
uv run boundarycheck test --config examples/lab.yaml --transport fixture
```

Real output on the patched lab (419 cases: 240 reads, 81 refused writes, 98 concealment comparisons):

```text
boundarycheck 0.1.0 | scope lab-demo | transport fixture:tenant-boundary-lab:patched
cases: no_issue_observed: 419, finding_candidate: 0, policy_denied: 0, not_run: 0, incomplete: 0, error: 0, inconclusive: 0 (total 419)
  note: 7 write combination(s) that the policy allows were not exercised by design: write checks send only requests the policy says must be refused.
exit code 0. Note: no_issue_observed does not mean the target is secure.
```

Now break one control on purpose and watch it get caught (flags: `TENANT_PREDICATE_OMITTED`,
`ROLE_CHECK_MISSING`, `PRIVATE_PROPERTY_SERIALIZED`, `MARKET_BOUNDARY_OMITTED`,
`WRITE_BEFORE_AUTHORIZATION`):

```bash
uv run boundarycheck test --config examples/lab-vulnerable.yaml --transport fixture --fixture-flaws ROLE_CHECK_MISSING
```

```text
cases: no_issue_observed: 281, finding_candidate: 5, ... (total 286)
  FINDING BC-0067 BC-ROLE-01 [high] bob:contact.private.read:PA1: expected deny_forbidden (role_denied), observed allow (HTTP 200): access was granted where the policy denies it
  FINDING BC-0076 BC-ROLE-01 [high] bob:project.write:PA1: expected deny_forbidden (role_denied), observed allow (HTTP 200): access was granted where the policy denies it; state changed: projects:... (modified)
  ...
exit code 1.
```

The fifth flaw is the interesting one: the lab **writes first and then refuses**, so every response is
the correct `403`/`404`. A status-only runner calls it clean (try `--reads-only`: 249 clean, exit 0).
The state diff finds it:

```bash
uv run boundarycheck test --config examples/lab-vulnerable.yaml --transport fixture --fixture-flaws WRITE_BEFORE_AUTHORIZATION
```

```text
cases: no_issue_observed: 265, finding_candidate: 21, ... (total 286)
  FINDING BC-0076 BC-MUTATION-01 [high] bob:project.write:PA1: the request was not accepted (HTTP 403) but state changed: projects:... (modified)
  ...
exit code 1.
```

## Use it on your own API

```bash
uv run boundarycheck init --output boundarycheck.yaml     # an annotated starter, safe by default
$EDITOR boundarycheck.yaml                                # your tenants, test users, objects, routes and policy
uv run boundarycheck validate --config boundarycheck.yaml # schema + references + policy completeness. No network
uv run boundarycheck plan     --config boundarycheck.yaml # prints every request. Sends nothing
export BC_TOKEN_ALICE=...  BC_TOKEN_BOB=...               # TEST users' tokens, read from the environment only
uv run boundarycheck test     --config boundarycheck.yaml --transport live
uv run boundarycheck list-runs ; uv run boundarycheck report --run RUN_ID --format md
```

The config holds **no secrets**: a principal names the environment variable its token comes from.
The policy is the heart of it, so write it from your requirements, not from the code under test.
[`examples/lab.yaml`](examples/lab.yaml) is a complete, commented example.

## Reading a result

| Status | Meaning |
|---|---|
| `no_issue_observed` | The response matched the declared policy. **Not** "secure". |
| `finding_candidate` | The response differed from the policy. A human reviews it (`review_state: needs_review`). |
| `inconclusive` | It ran but the answer cannot be mapped to a decision (for example HTTP 422, 429, 5xx, a non-JSON body). |
| `incomplete` | A timeout, connection failure or oversized response. |
| `policy_denied` | The tool refused to send it (budget exhausted, a redirect, a forbidden method or path). |
| `not_run` | Skipped for a stated reason, usually no credential for that user. |
| `error` | The tool itself failed (including a redaction failure). |

**Exit code:** `0` only if there is at least one case and *every* case is `no_issue_observed`; `1` if
any case is a `finding_candidate`; `2` for everything else (any other status, an unreadable config, a
usage error, a crash). Wire `0` into CI; treat `1` and `2` as red.

Two situations are worth knowing, and both are tested and documented rather than hidden:

* **A wrong policy looks like a vulnerable API.** The tool judges against the policy it was given.
  Tell it that viewers may read private contacts and a *correct* API is reported as a (low-severity)
  `finding_candidate`. That is why a finding is a candidate and, for a mismatch with the policy, confidence is
  never `high`. The one exception is `BC-MUTATION-01` (a refused request that still changed state), which
  does not depend on the policy being right (D-B18).
* **An answer the tool cannot map is `inconclusive`, never clean.** The lab answers `422` for an id
  that is not a UUID; those cases are `inconclusive` and the run exits `2`.

## How it stays safe

* **Loopback-only and read-only on a live target.** Only `GET`/`HEAD`, and never a request body: a write
  is sent only by the in-process fixture, only where the policy says it must be refused, and its effect
  is judged by a raw-SQL snapshot diff. The base URL must be `http://` on `127.0.0.0/8`,
  `::1` or `localhost`. A name is resolved once, every address must be loopback, and the connection
  goes to the checked IP literal; the connected peer is verified again. Redirects are never followed,
  proxy variables are ignored, bodies are capped *after* decompression, and there is a timeout, a rate
  limit and a hard request budget. **These are properties of the tool's own sockets.** It cannot see
  where a loopback listener forwards: an `ssh -L` tunnel or a local proxy on `127.0.0.1` can still
  reach a remote host. Do not point it at one unless you are authorized for what is behind it.
* **A hostile config is parsed defensively.** Size cap, no YAML tags, aliases, anchors, merge keys or
  duplicate keys, nesting cap, strict types, every identifier and path validated, only read methods.
* **Credentials never touch disk or output.** They are replaced in everything that is stored, and
  before anything is written every credential used in the run is searched for in the report and the
  evidence; if one is found nothing is written and the run exits `2`.
* **Reports contain no response bodies**: statuses, rule ids, the *names* of fields, and SHA-256
  references to the redacted evidence. Run directories are `0700`, files `0600`, a world-writable runs
  directory is refused, and `purge --older-than` bounds retention.

## Documentation

* [docs/contract.md](docs/contract.md): the behaviour the tests pin (oracle, comparator, transports, redaction).
* [LIMITATIONS.md](LIMITATIONS.md): what a clean run does **not** show. Read it before relying on a result.
* [DECISIONS.md](DECISIONS.md): choices and the reasons, including the ones awaiting the owner's confirmation.
* [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md), [CHANGELOG.md](CHANGELOG.md).

## Development

```bash
git clone --recurse-submodules https://github.com/MDPorsch/boundarycheck && cd boundarycheck
uv sync
uv run pytest -q                                  # unit, negative, integration (against the lab) and packaging tests
uv run ruff check . && uv run ruff format --check . && uv run mypy
uv run python tools/mutation.py                   # optional, ~30 min: inject 145 security bugs, expect every one caught
uv run python tools/secret_scan.py                # optional: gitleaks over all history + tree (brew install gitleaks)
```

The lab is a pinned git submodule at `lab/`, installed **editable and for development only**, so
installing `boundarycheck` never installs the lab and never installs the deliberately vulnerable variant.
A wheel install can validate configs, plan, and run `--transport live`; the `fixture` transport needs a
source checkout and says so clearly if it is missing.

## Licence

[Apache License 2.0](LICENSE) ([NOTICE](NOTICE)). The licence choice is recorded as D-B10 and was confirmed by the
owner.
