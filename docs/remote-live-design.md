# Remote live mode: design for your review

**Status: approved by the owner on 2026-11-20 (D-B19 to D-B24), implemented and released in 0.2.0.** You asked for live mode to "work outside localhost but still
secure", for many external assessments. That changes **egress** (the tool will open connections to
networks you do not control) and **token handling** (a test user's token will cross a network), both
of which you told me to stop and review before shipping. So this is a design plus an implementation on
the branch `remote-live`, behind a pull request that I will **not merge or release** until you say so.
Nothing here is in `main`, and nothing is published.

## 1. Goal and non-goals

**Goal.** Run the same read-only boundary checks against **one declared remote API** (staging, a client
test environment, an internal service over a VPN) and keep the guarantees that make the tool safe to
point at someone else's system: it cannot be talked into a different host, a different network, a
weaker connection, or a heavier load than the assessor wrote down.

**Non-goals (v0.2).** Writes to a remote host (a state diff cannot be taken from outside, D-B16);
several hosts in one run; discovery or crawling; credential attacks; proxies; any model or third-party
call; turning TLS verification off.

## 2. What changes, and what does not

| | v0.1 (loopback) | v0.2 remote |
|---|---|---|
| Methods | `GET`, `HEAD`, no body | **unchanged** |
| Scheme | `http` on loopback | loopback: `http` as before. **Anything else: `https` only** |
| Which hosts | `127.0.0.0/8`, `::1`, `localhost` | **the one host you declare, twice** (see 4.1) |
| Which addresses it may connect to | loopback | **public addresses**, plus private ranges **only if you list them** (see 4.3) |
| Authorization | not needed (nothing left the machine) | **declared in the config and acknowledged on every run** (see 4.2) |
| Redirects, proxies, body cap, timeout, rate, budget | as built | unchanged, with a **lower default rate** and a **hard cap** |
| Credentials | environment variables only | unchanged; **sent only to the declared host, only over verified TLS** |

## 3. Threats this design answers

| # | Threat | Where it is answered |
|---|---|---|
| T1 | A typo or a copied config sends test tokens to the wrong host | 4.1 (declared twice), 4.2 (acknowledged each run) |
| T2 | SSRF-style reach into a network the assessor did not mean: the name resolves to `127.0.0.1`, a private range, or the cloud metadata address `169.254.169.254` | 4.3 |
| T3 | DNS rebinding: the name resolves to a public address when checked and a private one when connected | 4.3 (one resolution, connect to the checked address) |
| T4 | A token sent in clear text, to a man in the middle, or to a host with a bad certificate | 4.4 |
| T5 | A redirect carries the tool, and its token, to another host | 4.5 |
| T6 | Running outside the engagement window, or by accident from CI | 4.2 |
| T7 | Load on a client system | 4.6 |
| T8 | A hostile response: huge, compressed bomb, slow, or full of markup | unchanged from v0.1 (body cap after decompression, total timeout, sanitised names) |
| T9 | The tool becomes a scanner for hosts you are not authorised to test | 4.1 (exactly one host, no wildcards, no discovery) |
| T10 | Client data lands in your reports and evidence | 4.7 |
| T11 | IPv6 tricks: IPv4-mapped, NAT64, 6to4, Teredo, zone ids | 4.3 |

## 4. The controls

### 4.1 One host, declared twice

```yaml
scope:
  id: acme-q4
  target:
    label: ACME staging API
    base_url: https://api.staging.acme.example          # the one place requests go
    allowed_hosts: [api.staging.acme.example]            # exact, lower-case ASCII, no wildcard
```

`base_url` must be `https://host[:port]` with **no** user-info, path, query or fragment, and its
`host:port` must appear in `allowed_hosts` (port 443 is implied; any other port is written out, for
example `api.acme.example:8443`). Wildcards, non-ASCII names (write the `xn--` form) and IP literals
that are not also in `allowed_networks` are refused. Declaring the destination twice means an edit
to one line alone can never retarget a run. `allowed_hosts` has exactly the one entry in v0.2: a list
that could grow is a scanner.

### 4.2 Authorization: declared, acknowledged, time-boxed

```yaml
  authorization:
    engagement: "ACME-2026-114"        # your reference (a statement of work, a ticket); free text
    not_before: 2026-11-20T00:00:00Z   # optional
    not_after:  2026-12-04T23:59:59Z   # required: forces you to decide when it ends
```

* A remote run needs the `authorization` block **and** `--ack-authorization` on the command line.
  The flag is the human saying "yes, now"; the block is what the report will quote. A config copied
  into CI does nothing remote without the flag.
* The run refuses outside `not_before`..`not_after` (UTC), and refuses a `not_after` more than 366 days
  away (an engagement is not forever); when both ends are given they may be at most 366 days apart.
* The report header says: *"Remote run. Authorization was declared by the operator for engagement
  ACME-2026-114 (valid ...). The tool does not and cannot verify it."* It is attestation, not proof,
  and says so.
* Loopback runs need none of this, as before.

### 4.3 Which addresses it will connect to

The name is resolved **once**, by the tool. **Every** address it returns must pass, or nothing is sent.
The connection then goes to the **checked IP literal**, so there is no second lookup to rebind, and the
connected peer is verified again after the connection (as in v0.1).

* **Always refused, even if you list them:** `0.0.0.0/8`, link-local `169.254.0.0/16` and `fe80::/10`
  (this is where cloud metadata services live), multicast, broadcast, the unspecified address,
  and any IPv6 form that **embeds** an IPv4 address (IPv4-mapped `::ffff:0:0/96`, NAT64 `64:ff9b::/96`,
  6to4 `2002::/16`, Teredo `2001::/32`): the embedded address is judged by the same rules, and
  because those forms exist to reach IPv4 hosts through a gateway, they are refused outright rather
  than trusted. IPv6 zone ids (`%eth0`) are refused.
* **Allowed by default:** globally routable addresses (Python's `is_global`).
* **Allowed only if you write the range down:** loopback, RFC 1918 (`10/8`, `172.16/12`,
  `192.168/16`), shared address space `100.64/10`, unique-local `fc00::/7`:

  ```yaml
      allowed_networks: [10.20.0.0/16]    # a staging network reached over your VPN
  ```

  Every resolved address must fall in a listed range. The ranges that are never allowed (above) are
  refused even inside a listed range.

### 4.4 TLS, always verified

* `https` only for anything that is not loopback. There is no `http` remote option and no
  `--insecure`.
* The certificate is verified against the system trust store (plus an optional `ca_bundle` file for a
  private CA, which **adds** trust, never removes verification). The **host name** checked is the
  declared one, sent as SNI and `Host`, while the TCP connection goes to the pinned address.
* TLS 1.2 or newer. Tokens are sent only after the handshake verified, so a failed handshake sends
  nothing.

### 4.5 Redirects and proxies

Never followed, as in v0.1: a 3xx is `policy_denied`, and the token never leaves the declared host.
Proxy environment variables are ignored. A corporate proxy is **not** supported in v0.2 (it would sit
between the tool and the certificate it verifies); say if you need one.

### 4.6 Load

Defaults for a remote run: **2 requests per second**, a budget of **500** requests, serial, one
connection. The config may raise the rate to at most **20**. The budget is a hard stop.

### 4.7 What lands on your disk

Unchanged: reports hold statuses, rule ids, field **names** and SHA-256 references, no bodies;
evidence is redacted before it is stored, in a `0700` directory; `purge --older-than` bounds retention.
A remote run adds the **host name, the addresses it resolved and the engagement reference** to the
report. For client work, plan to `purge` after the report is delivered; the tool cannot know your
contract's retention terms.

## 5. Ease of use

* `boundarycheck init --remote` writes an annotated starter with the block above.
* `boundarycheck preflight --config x.yaml` checks the config, the window and the allow-list,
  **resolves the name** and prints the addresses and the verdict for each, and sends **no request**.
  It is the safe way to see what a run would do.
* A remote `test` prints, before the first request, the exact `host:port`, the pinned address and the
  engagement reference it is about to use.

## 6. What this does not guarantee

* **Authorization.** The tool cannot verify that you may test the host. You attest; the report says so.
* **A compromised machine.** These are properties of the tool's own sockets. A container or firewall
  that allows only the declared host is the real containment; recommended, not enforced.
* **A client whose DNS is poisoned to a different public address.** The token would reach that address;
  the certificate check is what stops it (the attacker cannot present a valid certificate for the host).
  This is why TLS verification cannot be switched off and why `ca_bundle` is a trust decision you make.
* **Shared hosting and CDNs.** A public address cannot be pinned to "the client's" machine.
* **Your clock.** The authorization window uses the local clock.
* **Side effects of reads.** A `GET` that triggers something on the client's side is their API's
  design; the tool sends only requests built from your declared actions.

## 7. Tests this design commits to (written first, red first)

Egress: every always-refused range (each address family form), a private range refused without
`allowed_networks` and accepted with it, a name with **one** private address among public ones refused,
DNS that answers differently the second time (rebinding: one resolution only, the second answer never
used), user-info, wildcard, non-ASCII, `host` not in `allowed_hosts`, `base_url` and `allowed_hosts`
mismatch, a second entry in `allowed_hosts`. TLS: a good certificate accepted, an untrusted CA, a wrong
host name, an expired certificate and a plaintext server all end as `incomplete` **with no token ever
received by the server**; a `ca_bundle` adds exactly its CA. Authorization: no block, no flag, expired,
not yet valid, loopback needing neither. Load: default rate, the cap, the budget. Redirect to another
host: refused, token not sent there. The independence and mutation suites extend to every new rule.

## 8. Decisions I need from you

| ID | Decision | My recommendation |
|---|---|---|
| D-B19 | HTTPS only, certificate always verified, no insecure option | yes |
| D-B20 | Public addresses by default; private ranges only when listed; metadata, link-local and IPv4-embedding IPv6 never | yes |
| D-B21 | One declared host, written twice, no wildcard | yes (a list is a scanner) |
| D-B22 | Authorization block with a required `not_after`, plus `--ack-authorization` every run | yes |
| D-B23 | Reads only on a remote host; no proxy support | yes for v0.2 |
| D-B24 | Rate default 2/s, cap 20/s, budget 500 | yes; tell me your clients' usual limits |

## 9. Rollout (done)

1. You read this and the branch; ask for changes.
2. I merge only after you say so, then tag `v0.2.0`. A version with remote live is never published
   by me without that.
3. `v0.1.0` (loopback only, M4 included) can be published first; it does not depend on any of this.

## 10. Implementation status (on this branch, measured)

| | |
|---|---|
| Tests | **656 pass** at merge (the 479 of 0.1.0 plus 177 for this feature: the address policy, config validation, the transport against real TLS servers, the CLI and the report) |
| Static | ruff and strict mypy clean; coverage 97%; the secret scan is clean |
| Mutation check | **189 mutants, all killed** (3 survived the first run and exposed gaps in my tests: a host that is only valid as a URL host, a zone id on a public address, the default-port `Host` header; each is now tested) |
| Real TLS | tested against throwaway servers on 127.0.0.1 with generated certificates (a good one, an untrusted authority, a wrong name, an expired certificate, a plaintext server, a private authority); in every refusal the server received **no request**, so no token was sent |
| **Not tested** | CDNs, a real client network, a private certificate authority in the field, a corporate network with its own DNS |
| Real server | one real run on 2026-11-20: a single anonymous `GET` of `https://api.github.com/zen`, a public endpoint meant for unauthenticated reads. The real certificate chain verified, the name was pinned to the address it resolved to, and the report carried the declaration and the address. That is one host on one day, not a field test |
| **Decisions** | D-B19 to D-B24 (section 8): approved by the owner on 2026-11-20 ("I agree with the safety rules") |

