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

### Not yet
- Writes of any kind, remote hosts, OS-keychain credentials, OpenAPI import, SARIF, PyPI publication.
