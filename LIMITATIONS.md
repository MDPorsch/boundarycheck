# Limitations

What a result from this tool does **not** show. Each item is a known boundary of v0.1, stated so that a
clean run is not mistaken for more than it is. Items are referenced from the code and the tests.

## About what a result means

* **BL-01 `no_issue_observed` is not "secure".** It means the response to one request matched the policy.
  Every report says so.
* **BL-02 The policy is the assessor's.** The tool cannot tell a wrong policy from a vulnerable API. A policy
  that says viewers may read private contacts makes a correct API look broken (a low-severity candidate;
  tested and documented in `tests/integration/test_lab_fixture.py`). Confidence is never `high` for a mismatch with the policy; `BC-MUTATION-01` is `high` because it does not depend on the policy (D-B18).
* **BL-03 One observation per case.** No retries and no statistics. A flaky target produces `incomplete` or
  `inconclusive`, never a clean result, but a rare race is simply not observed.
* **BL-04 Only what is declared is tested.** Routes, objects and principals that are not in the config are
  not exercised. There is no discovery by design.

## About coverage

* **BL-05 Writes are checked on the in-process fixture only, and only the refused ones.** A live target
  is sent `GET`/`HEAD` only, so against a live target **no write-path flaw is detected**: a declared
  write check there is `not_run` (exit `2`) or left out with `--reads-only`. On the fixture, write cases
  are the requests the policy says must be refused; a write the policy *allows* is never sent (the run
  says how many), so a broken *allowed* write (a legitimate user denied) is not tested. The state diff
  covers every table except `audit_events` and `alembic_version`; a side effect outside the database
  (a queue, a file, another service) is invisible to it.
* **BL-06 Not timing, concurrency or resource limits.** No timing channel, race, quota or rate-limit
  testing. Concealment compares status, selected headers and body shape, not response time.
* **BL-07 First page of a list only.** A list is checked against the declared objects for the first page the
  API returns; pagination is not followed.
* **BL-08 The authorization model is deliberately small.** Membership with a role per tenant, a tenant
  state, per-tenant allowed attribute values, role capabilities, and minimum-role field floors. Hierarchical
  or attribute-based policies that do not fit that shape cannot be expressed. A resource that does not
  declare a scoped attribute is not subject to it (so a forgotten attribute shows up as a low-severity
  "denied where the policy allows it", not as a silent hide).
* **BL-09 JSON APIs only.** A 2xx whose body is not a JSON object cannot have its fields checked and is
  `inconclusive`.
* **BL-10 Field checks report names, not values**, and judge exposure by the declared minimum role for the
  field path. They do not detect a secret placed in an allowed field.

## About the network

* **BL-11 Loopback-only is a property of the tool's own sockets.** The tool connects only to loopback
  addresses, resolves a name once, connects to the checked literal and verifies the peer. It **cannot see
  where a loopback listener forwards**: an `ssh -L` tunnel, a local proxy or a port-forward on `127.0.0.1`
  can reach a remote host. Do not aim it at one unless you are authorized for what is behind it. A
  container or a network ACL outside the process is the supported containment.
* **BL-12 `http://` only on loopback.** TLS on loopback is not supported; a remote host is `https://` only (proposed, `docs/remote-live-design.md`).
* **BL-12a Remote mode: the authorization is the operator's word.** The tool enforces the declared window
  and says in every report that it cannot verify the declaration. It cannot know whether you may test
  the host.
* **BL-12b Remote mode: addresses and names.** Every address a name resolves to must pass the policy, but
  a name that a hostile DNS points at a different *public* address is stopped only by the certificate
  check, which is why verification cannot be turned off and why a `ca_bundle` is a trust decision. A CDN
  or shared host cannot be pinned to "the client's machine".
* **BL-12c Remote mode: no proxy, no writes, one host.** A corporate proxy would sit between the tool and
  the certificate it verifies, so none is supported; writes to a remote host are never sent (no state
  snapshot can be taken from outside); one host per run.
* **BL-12d Remote mode: your clock and your disk.** The window uses the local clock. The report names
  the host, the resolved address and the engagement; reports and evidence stay on your machine until
  you `purge` them, which a client contract may require.
* **BL-13 Not a defence against a hostile local machine.** A local attacker who can read the process,
  the environment or the runs directory is out of scope.

## About evidence and reports

* **BL-14 Redaction is best effort.** It removes known credential values, JWT shapes, e-mail addresses,
  long hex/base64 runs and fields you name. It cannot know every secret shape. The leak guard is the
  backstop but only knows the credentials used in the run.
* **BL-15 Evidence hashes prove integrity, not origin.** A SHA-256 shows the stored bytes were not
  altered. It does not prove where they came from.
* **BL-16 Evidence hashes differ between runs** when the target puts per-request values (a request id) in
  responses, because the stored evidence is the real (redacted) response. Verdicts, details, rule ids and
  severities are identical between runs (tested).

## About the lab fixture

* **BL-17 The fixture transport needs a source checkout.** The lab is a git submodule installed editable
  for development; the lab's own wheel excludes the deliberately vulnerable variant, so a wheel install of
  boundarycheck cannot run it (it says so, exit 2).
* **BL-18 The vulnerable variant serves six routes.** It does not implement the audit and nested-invoice
  read routes, which is why `examples/lab-vulnerable.yaml` omits them (a test keeps the two examples in step).
* **BL-19 The detection claims are about this lab.** "Detects the four flaws" means exactly that, on this
  reference target. It is not a measured detection rate on real APIs.

## About the platform

* **BL-20 Tested on macOS (development) and Linux (CI) with Python 3.13 only.** Windows and other interpreters are not tested.
