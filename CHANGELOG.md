# Changelog

All notable changes are recorded here. The format follows Keep a Changelog; versions follow SemVer
once a release is tagged. Nothing has been published to PyPI.

## [Unreleased] - 0.1.0.dev0

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
