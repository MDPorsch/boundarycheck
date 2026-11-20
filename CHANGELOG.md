# Changelog

All notable changes are recorded here. The format follows Keep a Changelog; versions follow SemVer.

## [0.3.0] - unreleased

Five features (design: `docs/design-v0.3.md`; credential handling and SARIF privacy await the owner's review).

### Added
- **Root path.** An action may request `/`.
- **Credential schemes.** `in: header` (an API key, optionally with a `prefix`) and `in: cookie`, besides the bearer
  default. Forbidden header names, cookie-injection characters and query-string keys are refused. The tool never
  logs in.
- **OS keychain credentials** (optional extra `boundarycheck[keychain]`): `credential: {keychain: {...}}`, and
  `boundarycheck keychain set|check|delete`. Real OS stores only; never a plaintext backend.
- **SARIF 2.1.0** (`report.sarif`, `report --format sarif`, `--sarif-uri`): findings as results, everything else
  that was not clean as notifications, stable fingerprints, a privacy notice inside the file. Validated against
  the official schema in the tests.
- **OpenAPI import** (`boundarycheck import-openapi`): a skeleton with fail-loud placeholders, hardened against an
  untrusted document, never fetching and never writing a remote address.

### Changed
- `Redactor` and the leak guard now also cover keychain values and `report.sarif`; `_run_live` returns the
  transport's own secrets for the run store.

## [0.2.0] - 2026-11-20

### Added: remote live mode (design approved by the owner, D-B19 to D-B24)
- One declared remote host (`base_url` plus `allowed_hosts`, written twice), https only with the certificate
  and host name always verified (an optional `ca_bundle` adds a private authority; nothing turns verification
  off), the name resolved once and every address judged: public by default, private ranges only when listed
  in `allowed_networks`, link-local (cloud metadata), multicast, reserved and IPv4-embedding IPv6 never.
- An `authorization` block (`engagement`, `not_after`, optional `not_before`) plus `--ack-authorization` on
  every run; the run refuses outside the window; the report says the declaration is the operator's and is not
  verified, and names the host and the pinned address.
- A lower default rate for a remote host (2 per second, at most 20); reads only, never a body, no proxy.
- `boundarycheck preflight` (resolves and judges every address, sends no request) and `init --remote`.
- 177 new tests (656 in all), 189 mutants of the new and changed code all killed, one real run against a
  public HTTPS endpoint.

### Changed
- Superseded v0.1 pins: "a remote host is refused with the word loopback" (now: refused unless declared
  completely) and three mutants of the old parser.

## [0.1.0] - 2026-11-20

First release. The owner confirmed the licence (Apache-2.0) and approved publishing to PyPI on
2026-11-20; publication uses trusted publishing through a protected environment (`docs/releasing.md`).

### Added
- Hardened YAML config loader (size cap, no tags/aliases/anchors/merge keys/duplicate keys, depth cap,
  strict schema, validated identifiers and paths, GET/HEAD only, loopback-only base URL).
- Independent oracle (declared policy) and comparator (status, field projection, list contents,
  concealment of hidden vs missing objects).
- Seven-state result model and exit codes 0/1/2.
- Loopback-only live transport (single resolution, connected-peer check, no redirects, no proxy
  variables, decompression-bounded body cap, total timeout, rate limit, request budget).
- Built-in `tenant-boundary-lab` fixture adapter (in process, ephemeral keys).
- Redaction, a credential-leak guard, a content-addressed evidence store with private permissions,
  JSON and Markdown reports.
- CLI: `init`, `validate`, `plan`, `test`, `report`, `list-runs`, `purge`.
- Mutation tool (98 injected bugs) and a secret scan.

### M4: write checks and the state diff (fixture transport only)
- Write actions (`POST`, `PUT`, `PATCH`, `DELETE`) with a static JSON `body` in the config. Only requests
  the policy says must be refused are planned; a write the policy allows is never sent and is counted.
- A raw-SQL state diff over the lab's database (every table except `audit_events` and `alembic_version`),
  taken before and after each write case, with a restore-and-verify step between cases.
- New rule `BC-MUTATION-01` (a refused or failed request that still changed state), severity high,
  confidence high. It finds the lab's fifth flaw `WRITE_BEFORE_AUTHORIZATION`, whose status codes are
  exactly right; a read-only run is clean against it. The write exploits of `ROLE_CHECK_MISSING`,
  `TENANT_PREDICATE_OMITTED` and `MARKET_BOUNDARY_OMITTED` are now detected as well.
- `--reads-only`; `state_changes` on every case in the JSON report (additive, schema_version stays "1");
  `plan` shows that a request carries a body (its size, never its content).
- The live transport still refuses every method but `GET`/`HEAD` and now refuses a body. A declared write
  check against a live target is `not_run`.
- Changed pins (the contract changed): "a config may only name GET and HEAD" and its mutant
  `config_write_methods_allowed` were retired; `test_live_without_credentials_cannot_be_clean` uses
  `--reads-only` so its first `not_run` is still the credential one.

### Not yet
- Remote hosts, OS-keychain credentials, OpenAPI import, SARIF, PyPI publication.
