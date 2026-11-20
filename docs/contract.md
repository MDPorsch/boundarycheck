# Contract (v0.1)

This page is written **before** the code and the tests. Every sentence with "must" is pinned by a test
in `tests/`; a test written red-first carries `@pytest.mark.milestone("S1")` and was committed failing.
Design background and the owner's decisions are in
[`lab/docs/productization/boundarycheck-design.md`](../lab/docs/productization/boundarycheck-design.md).

## 1. What a run is

`boundarycheck test` plans a bounded set of requests (principal x action x resource), **reads everywhere and
refused writes on the in-process fixture only** (s9),
sends each, and compares what the target did with what an **independent, declared policy** says it
should do. The policy is written by the assessor in the config file. The tool never derives an
expectation from the target.

## 2. Vocabulary

| Outcome (a decision) | Typical HTTP status |
|---|---|
| `allow` | 2xx |
| `deny_unauthenticated` | 401 |
| `deny_forbidden` | 403 |
| `deny_not_found` | 404 |

Any other status (3xx, 400, 405, 409, 410, 413, 415, 422, 429, 5xx...) is **not mapped** to an
outcome. A status code is never trusted alone: an `allow` is also checked against the declared field
projection and, for list routes, against the declared set of objects the principal may see.

| Case status | Meaning |
|---|---|
| `no_issue_observed` | Observed equals expected. **Not** "secure". |
| `finding_candidate` | Observed differs from expected. A human reviews it (`review_state: needs_review`). |
| `policy_denied` | The tool refused to send (budget exhausted, redirect refused, method or path refused). |
| `not_run` | Skipped for a stated reason (no credential for this principal on this transport). |
| `incomplete` | Started but did not finish (timeout, connection failure, body over the size cap). |
| `error` | The tool failed (including a redaction failure or a secret that would have been written). |
| `inconclusive` | Ran, but the response cannot be mapped to a decision (unmapped status, unparseable body, a list that names objects the config does not declare). The default whenever a status is ambiguous. |

**Exit code:** `0` only if there is at least one case and **every** case is `no_issue_observed`; `1` if
any case is `finding_candidate` (this wins over `2`); `2` for everything else, including an empty plan,
an unreadable config and any usage error. A failed or partial run can never exit `0`.

## 3. The oracle (expected decision)

For `(principal, action, resource)` the declared policy is evaluated in this fixed order and the first
failing step decides (reason in parentheses):

1. no credential (the implicit principal `anonymous`) -> `deny_unauthenticated` (`unauthenticated`)
2. principal `status` is not `active` -> `deny_forbidden` (`principal_inactive`), even for a missing object
3. no **active** membership in the resource's tenant, or the resource does not exist
   -> `deny_not_found` (`no_membership`); `deny_forbidden` if `policy.hidden_is_not_found` is false
4. tenant `state` is not `active` -> `deny_forbidden` (`tenant_inactive`)
5. a resource attribute is outside the tenant's `allowed` values -> `deny_not_found` (`scope_hidden`)
6. the member's role is not in `policy.capabilities[capability]` -> `deny_forbidden` (`role_denied`)
7. otherwise `allow` (`allowed`) with the visible fields for that role (`policy.fields[surface]`: a field
   is visible from its minimum role upward in `policy.roles`) and, for a list action, the set of objects
   the principal may see.

Unknown roles, capabilities and surfaces are denied (default deny). The oracle imports nothing from the
target, the transports or the engine (`tests/unit/test_independence.py`).

## 4. The comparator

* A status is mapped to an outcome as in s2. An unmapped status is `inconclusive`.
* Expected `allow`, observed `allow`: every field path in the JSON body must be in the visible set
  (exposure of an undeclared field is a finding; the finding names the **path**, never the value). For a
  list action: every returned id must be a declared object the principal may see, and `total` (if
  declared) must equal the number of such objects.
* Expected a denial, observed another outcome (including a different denial) is a finding. A 403 where
  a 404 was expected is an existence oracle and is reported as such.
* **Concealment:** for every hidden (but existing) resource that must answer `deny_not_found`, the
  response must be indistinguishable from the response for a declared **missing** resource of the same
  kind (status, selected headers and body shape, with request ids removed). A difference is a finding.

## 5. Transports and egress

* **Fixture transport** (`--transport fixture`): the built-in `tenant-boundary-lab` adapter runs the lab
  in process (no socket, ephemeral Ed25519 key, temporary SQLite database). It needs the lab installed
  from a source checkout; without it the run exits `2` with a message that says so.
* **Live transport** (`--transport live`) has two modes. **Loopback** (v0.1, unchanged):
  * the base URL must be `http://` with a loopback IP literal (`127.0.0.0/8`, `::1`) or the name
    `localhost`; any other host is refused at config load and again at run time;
  * a name is resolved by the tool, **every** address must be loopback, and the connection is made to
    the checked IP literal, so there is no second resolution to rebind; the connected peer is checked
    again after the response;
  * `GET` and `HEAD` only; paths are built from validated templates and identifiers (no scheme,
    authority, `..`, backslash, control character or percent-escape can be injected);
  * redirects are never followed (a redirect is `policy_denied`); proxy environment variables are
    ignored; `Accept-Encoding: identity`; the **decoded** body is capped (default 1 MiB) and a request
    has a timeout; a request budget (default 500) and a rate limit apply; the budget is a hard stop.
  **Remote** (v0.2, proposed: `docs/remote-live-design.md`, awaiting the owner's review), to ONE declared
  host and only then:
  * `base_url` is `https://host[:port]`; `scope.target.allowed_hosts` holds exactly one entry, the same
    host and port, in lowercase ASCII with no wildcard; an `authorization` block (an `engagement` and a
    `not_after`) is required and the run needs `--ack-authorization`; the run refuses outside the
    declared window (and a `not_after` more than 366 days away);
  * the name is resolved **once** and **every** address must pass: public addresses by default; private,
    loopback and shared ranges only if listed in `allowed_networks`; link-local (cloud metadata),
    multicast, reserved and every IPv6 form that embeds an IPv4 address (mapped, NAT64, 6to4, Teredo)
    never, and a listed range that would include one is refused at load;
  * the connection goes to the checked address, with TLS 1.2 or newer, the certificate and the declared
    **host name** always verified (an optional `ca_bundle` ADDS a private authority; nothing turns
    verification off), the host name sent as SNI and `Host`; the connected peer must be the checked
    address and pass the same policy;
  * reads only, never a body, redirects never followed, proxy variables ignored; a lower default rate
    (2 per second, at most 20) and the same budget, body cap and timeout;
  * the report states that the authorization is the operator's declaration, not verified, and names
    the host and the pinned address. `boundarycheck preflight` resolves and judges every address and sends
    **no request**.
* A timeout, connection failure or oversized body is `incomplete`; 429 and 5xx are `inconclusive`.
  Neither can ever be `no_issue_observed`.
* These are properties of the tool. The tool cannot make a hostile network safe; a container or a
  network ACL outside the process is the supported containment (see `LIMITATIONS.md`).

## 6. Config

YAML, loaded by a hardened loader: size cap (256 KiB) checked before parsing, `yaml.safe_load` semantics
only (no tags, no object construction), **aliases and anchors refused**, **duplicate keys refused**,
nesting depth capped, strict schema (`extra="forbid"`, no coercion: an unquoted `1234` where a string
is required is an error), every identifier validated against `[A-Za-z0-9_-][A-Za-z0-9._~-]{0,127}`,
only `GET`, `HEAD`, `POST`, `PUT`, `PATCH` and `DELETE` accepted (a write needs a state-aware transport,
s9; an optional `body` is a static JSON object, at most 4096 bytes and 6 levels deep, and only on a write).
**Credentials are never in the config**: a principal names an
environment variable (live) and/or a fixture key (fixture). Errors name the location and the problem,
never the offending value, and never carry a traceback to the user.

## 7. Redaction and evidence

* A response body, header or token is stored only **after** redaction: `Authorization`, `Cookie`,
  `Set-Cookie`, `Proxy-Authorization` values removed; JWT-shaped strings, e-mail addresses and long
  hex/base64 runs replaced; fields named in `redaction.mask_fields` masked at any depth.
* The evidence store keeps the redacted blob under its SHA-256 (a proof of the stored bytes' integrity,
  **not** of where they came from).
* Before anything is written, the serialized report and every blob are scanned for each credential
  value used in the run. If one is found, **nothing is written** and the run exits `2` with `error`.
  If redaction itself fails, that case is `error` and its blob is discarded.
* Runs live in `.boundarycheck/runs/RUN_ID/` (directories `0700`, files `0600`); a world-writable runs
  directory is refused; `purge --older-than` removes only directories that look like runs.

## 8. Reports

JSON is the source of truth (`schema_version`, tool version, scope id, target label, transport, an
explicit attestation line, per-case `id, rule_id, status, severity, confidence, expected, observed,
redacted_evidence_refs, limitations, review_state`, a summary and run-level limitations). Markdown is a
rendering of the same data. Every report states that `no_issue_observed` does not mean "secure", that
the policy is the assessor's, and that writes are checked only on the fixture. Every case carries
`state_changes` (empty for a read): the table, primary key and kind of each row a write changed, never a
value. SARIF is not produced.

## 9. Write checks and the state diff (fixture transport only)

A config may declare **write actions** (`POST`, `PUT`, `PATCH`, `DELETE`) with an optional static JSON
`body`. The rules, all pinned by tests (`tests/unit/test_writes.py`, `tests/unit/test_statediff.py`,
`tests/integration/test_lab_writes.py`):

1. **Only the fixture transport ever sends a write.** The live transport refuses every method except
   `GET` and `HEAD` (`policy_denied`), exactly as before. A write is never sent to a remote host.
2. **Write cases are planned only where the policy says the request must be refused** (any `deny_*`).
   A combination the policy *allows* is never sent: it would change the target's state and test
   functionality, not a boundary. The run states how many such combinations were not exercised.
3. A transport is **state-aware** if it can take a snapshot and restore a pristine state. The fixture
   transport reads the lab's database with raw SQL, **independently of the target's own code**. Before
   each write case the state is pristine; after it the engine snapshots and diffs. Tables named
   `audit_events` and `alembic_version` are excluded: a correct refusal appends an audit row.
4. Outcome of a write case that the policy says must be refused:

   | Observed | State | Result |
   |---|---|---|
   | the expected denial | unchanged | `no_issue_observed` |
   | any response that is **not a 2xx** (a refusal, an error, an unmapped status) | **changed** | `finding_candidate`, rule `BC-MUTATION-01`, severity high, confidence high: the target refused (or failed) and still persisted the write, whatever the declared policy says |
   | a 2xx | any | `finding_candidate` with the rule of the declared reason (`BC-ROLE-01`, `BC-TENANT-01`, ...); a changed state is added to the detail |
   | a different denial | unchanged | `finding_candidate` as for reads (an existence oracle, a wrong code) |
   | an unmapped status | unchanged | `inconclusive` |
   | snapshot taken before or after failed | n/a | `error`; never `no_issue_observed` |

5. After any case whose diff is not empty the engine **restores the pristine state and checks that it is
   pristine again**, so one flaw cannot colour the answers to later cases. A failed snapshot, a failed
   restore or a restore that does not restore halts the remaining write cases (`not_run`); a snapshot
   failure after a request is `error` for that case, while a change that was already seen stays a finding.
   A request that fails (an exception) after it wrote is still a finding.
6. A transport that is **not** state-aware gets `not_run` for every write case ("write checks need a
   state snapshot..."), checked before credentials, so the run exits `2` and no write was sent. `--reads-only` omits write
   cases instead, says so in the run limitations, and does not count them.
7. The diff names the **table, the primary key and the kind** (added, removed, modified). It never
   carries a value. Primary keys of the lab are synthetic ids; an adapter for a real system must not
   put anything sensitive in a key.
8. Concealment comparisons (s4) are derived from read cases only.

## 10. Not in v0.1

Writes to anything but the in-process fixture, remote hosts, credential attacks, route or host discovery,
any model or external API call, SARIF, OS-keychain credentials, and OpenAPI import. Write checks on a live
target are not offered because they need a state snapshot the tool cannot take from outside.
