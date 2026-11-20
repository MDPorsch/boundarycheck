# Limitations

What a result from this tool does **not** show. Each item is a known boundary of v0.1, stated so that a
clean run is not mistaken for more than it is. Items are referenced from the code and the tests.

## About what a result means

* **BL-01 `no_issue_observed` is not "secure".** It means the response to one request matched the policy.
  Every report says so.
* **BL-02 The policy is the assessor's.** The tool cannot tell a wrong policy from a vulnerable API. A policy
  that says viewers may read private contacts makes a correct API look broken (a low-severity candidate;
  tested and documented in `tests/integration/test_lab_fixture.py`). Confidence is never `high`.
* **BL-03 One observation per case.** No retries and no statistics. A flaky target produces `incomplete` or
  `inconclusive`, never a clean result, but a rare race is simply not observed.
* **BL-04 Only what is declared is tested.** Routes, objects and principals that are not in the config are
  not exercised. There is no discovery by design.

## About coverage

* **BL-05 Read-only.** v0.1 sends `GET`/`HEAD` only. Flaws that need a write to show are **not detected**.
  Concretely, the reference lab's `ROLE_CHECK_MISSING` and `TENANT_PREDICATE_OMITTED` flaws also let a
  viewer write and let a user in tenant A write to tenant B; boundarycheck detects their *read*
  consequences (private contacts, cross-tenant reads) and not the write exploits.
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
* **BL-12 `http://` only.** TLS on loopback is not supported in v0.1.
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
