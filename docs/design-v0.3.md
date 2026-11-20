# v0.3: five features, and the rules they follow

**Status: built on the branch `v0.3-features`, behind a draft pull request. Not merged, not released.**
Two of the five change how credentials are held and what a report reveals. You told me to stop and
review those before they ship, so the pull request waits for you (section 7).

| # | Feature | Touches a review-gated area? |
|---|---|---|
| 1 | Request the root path `/` | no |
| 2 | Cookie and API-key credentials | **yes: token handling** |
| 3 | OS-keychain credentials | **yes: token handling** |
| 4 | SARIF output | **yes: reporting privacy** |
| 5 | OpenAPI import | no (but it parses a file you did not write, so it is hardened like the config) |

## 1. The root path

`path: /` is accepted (a path needs no segment, so `GET /` and `GET /{tenant_id}` are expressible). Every
other rule about paths is unchanged: no `..`, no `//`, no query, no fragment, no escapes.

## 2. Cookie and API-key credentials

A principal's credential gets a **scheme**; the value still never appears in the config.

```yaml
principals:
  alice: {credential: {env: BC_TOKEN_ALICE}}                                   # Authorization: Bearer ...  (as before)
  bob:   {credential: {env: BC_KEY_BOB,   in: header, name: X-API-Key}}        # X-API-Key: <value>
  carol: {credential: {env: BC_COOKIE_C,  in: cookie, name: session}}          # Cookie: session=<value>
  dave:  {credential: {env: BC_DRF_D,     in: header, name: Authorization, prefix: "Token "}}   # Authorization: Token <value>
```

* **Header names** are plain header tokens. Names that would change how the request itself is framed or
  routed are refused: `Host`, `Content-Length`, `Content-Type`, `Transfer-Encoding`, `Connection`, `Upgrade`,
  `TE`, `Trailer`, `Accept`, `Accept-Encoding`, `User-Agent`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`.
* **Cookie values** may not contain `;`, `,`, spaces, quotes or backslashes (RFC 6265), so a value can never
  smuggle a second cookie into the request. A **header value** is printable ASCII with no control characters.
* **Query-string keys are not supported**: a key in a URL ends up in access logs, proxies and browser history.
* **The tool never logs in.** Exchanging a password for a session is a write with credentials in it; you
  supply the session cookie or the key. A cookie the target sets in a response is never stored or replayed.
* The same protections as a bearer token: leak guard on every report and every stored blob, `0600` files,
  refused over plain http except on loopback.

## 3. OS-keychain credentials

```yaml
principals:
  alice: {credential: {keychain: {service: boundarycheck, username: alice@acme}}}
```

```bash
pipx install "boundarycheck[keychain]"                # the optional extra (the `keyring` library)
boundarycheck keychain set   --username alice@acme    # hidden prompt; the value never touches a file or a command line
boundarycheck keychain check --username alice@acme    # exit 0 if it exists; never prints it
boundarycheck keychain delete --username alice@acme
```

* **Only real operating-system stores are accepted**: macOS Keychain, Windows Credential Locker, the Linux
  Secret Service and KWallet. A plaintext-file, "null" or "fail" backend is refused with a message; nothing is
  ever written to a file by this tool.
* The tool reads exactly the one service and username the config names, directly from the chosen backend (not
  through a chain that might fall back to a weaker one).
* A principal names **either** `env` **or** `keychain`, not both.
* Not available in the base install: without the extra, a `keychain:` credential is `not_run` with a message that
  says how to install it.

## 4. SARIF output

`boundarycheck test` writes `report.sarif` next to the JSON and Markdown reports; `boundarycheck report --run ID
--format sarif` prints it. SARIF 2.1.0, so it loads in GitHub code scanning, VS Code and most pipelines.

* **Findings are results**: severity high is `error`, medium `warning`, low `note`; the rule is the `BC-*` id,
  with a definition for every rule.
* **Nothing else is silently dropped.** An `inconclusive`, `incomplete`, `not_run`, `policy_denied` or `error`
  case becomes a tool notification, and the invocation records the exit code, so a run that was not clean never
  looks clean in a viewer.
* **Location**: the line of the action's declaration in your config (the policy it violated), plus a logical
  location `principal:action:resource`. `--sarif-uri PATH` sets the file path as it appears in your repository.
* A stable fingerprint per case, so a viewer can follow a finding from run to run.
* **No response bodies and no values**, exactly like the Markdown report: statuses, rule ids, names of fields,
  table, key and kind of changed rows.
* **Privacy warning, written into the docs and the file**: a SARIF file names your tenants, principals and
  routes. Uploading it to a **public** repository's code scanning publishes those names. For client work keep it
  private.

## 5. OpenAPI import

`boundarycheck import-openapi api.yaml --output boundarycheck.yaml` reads an OpenAPI 3.x document (JSON or
YAML) and writes a **skeleton** config. It never writes your policy, because a policy derived from the thing it
judges is not independent.

* The spec is **untrusted input**: a size cap before parsing, no YAML aliases or anchors, a depth cap, **local
  `$ref` only** (a remote or file reference is refused, never fetched), a cycle guard and a work cap. It opens
  no network connection and reads only the one file you name.
* Only `GET` and `HEAD` operations become actions; the rest are counted and listed as skipped.
* Names that do not fit the config's strict alphabets (a path with `:` or `%`, an odd property name) are
  skipped with a note, never passed through, so nothing from the spec can inject YAML.
* **Placeholders fail loud**: every capability is `[]` (nobody may) and every field needs the highest role, so
  a run before you edit the policy reports findings instead of a false clean.
* `securitySchemes` choose the credential scheme of the generated principals (bearer, header key, cookie). A
  query-string key or HTTP Basic is reported as unsupported.
* `servers` appear only in a comment. A **remote `base_url` is never filled in for you**: that is an egress
  decision, and it needs the declaration described in `docs/remote-live-design.md`.
* The output is parsed by the real config loader before it is written; if it would not validate, nothing is written.

## 6. What this does not do

* No login flows, no OAuth, no Basic or Digest, no client certificates, no query-string keys.
* A keychain value is only as safe as the operating system's keychain and your login.
* SARIF is not a vulnerability proof: every result is a `finding_candidate` that a person reviews.
* The OpenAPI skeleton knows the shape of the API, not who may see what. You still write the policy.

## 6b. What was measured

| Check | Result |
|---|---|
| Tests | 927 passed, 96% line and branch coverage (gate 90%) |
| Lint, format, strict mypy | clean |
| Mutation (`tools/mutation.py`) | 248 mutants, **248 killed**; the first full run left 2 alive (both OpenAPI importer), tests added, rerun killed both |
| SARIF | validated against the official OASIS 2.1.0 JSON schema in the tests |
| Secret scan | no findings in the tree or in history; the scanner caught its canary |
| Wheel | `boundarycheck-0.3.0`, `Provides-Extra: keychain`, no lab or test files; clean-venv smoke test passed |

Not measured: the keychain against a real operating-system store (the tests use an in-memory backend that is
accepted only by name), and the new credential schemes against a real remote API. Both need your machine or your
target.

## 7. Decisions I need from you

| ID | Decision | My recommendation |
|---|---|---|
| D-B25 | Allow the root path `/` | yes |
| D-B26 | Cookie and API-key credentials as in section 2 (no query keys, no login flow, forbidden header names) | yes |
| D-B27 | OS keychain as in section 3 (real OS backends only, optional extra) | yes |
| D-B28 | SARIF as in section 4 (findings as results, everything else as notifications, no values, privacy warning) | yes |
| D-B29 | OpenAPI import as in section 5 (skeleton only, fail-loud placeholders, no remote `base_url`) | yes |
| D-B30 | Version 0.3.0 and the `keychain` extra | yes |
