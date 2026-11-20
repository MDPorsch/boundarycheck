"""The annotated, safe-by-default starter config written by `boundarycheck init`."""

from __future__ import annotations

STARTER_CONFIG = """\
# boundarycheck starter config. Edit it, then:
#   boundarycheck validate --config boundarycheck.yaml
#   boundarycheck plan     --config boundarycheck.yaml     # prints every request; sends nothing
#   boundarycheck test     --config boundarycheck.yaml --transport live
#
# Use it ONLY against a system you own or are authorized to assess. v0.1 is loopback-only and
# read-only (GET/HEAD): point it at your own service running on this machine.
#
# This file holds NO secrets. A principal's token is read from the environment variable it names:
#   export BC_TOKEN_ALICE=...   (a test user's token, never your own)
version: 1

scope:
  id: my-first-check                      # names this assessment in every report
  target:
    label: my-service
    base_url: http://127.0.0.1:8000       # loopback only in v0.1
    request_budget: 500                   # hard stop on requests per run
    rate_limit_rps: 10

# Who owns what. This is what YOU say is true; the tool never believes the target about it.
tenants:
  - {key: A, state: active}
  - {key: B, state: active}

principals:                               # test users, never real people
  alice: {label: "tenant A owner",  credential: {env: BC_TOKEN_ALICE}}
  bob:   {label: "tenant A viewer", credential: {env: BC_TOKEN_BOB}}
  carol: {label: "tenant B owner",  credential: {env: BC_TOKEN_CAROL}}

memberships:
  - {principal: alice, tenant: A, role: owner,  status: active}
  - {principal: bob,   tenant: A, role: viewer, status: active}
  - {principal: carol, tenant: B, role: owner,  status: active}

# Objects that exist in your test data. Replace the ids. A resource with exists: false is a
# well-formed id that does not exist: it lets the tool check that a hidden object is
# indistinguishable from a missing one.
resources:
  - {key: PA1, kind: project, tenant: A, ids: {project_id: REPLACE-WITH-A-REAL-ID-IN-TENANT-A}}
  - {key: PB1, kind: project, tenant: B, ids: {project_id: REPLACE-WITH-A-REAL-ID-IN-TENANT-B}}
  - {key: project-missing, kind: project, exists: false, ids: {project_id: REPLACE-WITH-AN-ID-THAT-DOES-NOT-EXIST}}

# The read routes to check. {project_id} is filled from the resource's ids.
actions:
  - {id: project.read, method: GET, path: "/v1/projects/{project_id}", resource_kind: project, surface: project.detail}

# THE ORACLE: what the API is SUPPOSED to do. Write it from your requirements, not from the code.
policy:
  roles: [viewer, editor, admin, owner]   # ascending privilege
  hidden_is_not_found: true               # an object you may not see answers like a missing one (404)
  capabilities:                           # action id -> roles allowed
    project.read: [viewer, editor, admin, owner]
  fields:                                 # surface -> field -> the minimum role that may see it
    project.detail:
      id: viewer
      title: viewer
      status: viewer
  concealment:
    ignore_body_fields: [request_id]      # fields that differ on every response

redaction:
  mask_fields: []                         # e.g. [email, phone]: values are replaced before anything is stored
"""


_LOOPBACK_HEADER = """\
# Use it ONLY against a system you own or are authorized to assess. v0.1 is loopback-only and
# read-only (GET/HEAD): point it at your own service running on this machine.
"""
_REMOTE_HEADER = """\
# REMOTE TARGET. Use it ONLY against a system you are authorized to assess, for the engagement named
# below. Reads only (GET/HEAD), https only, one host. The authorization block is YOUR declaration: the
# tool enforces its window and cannot verify it. Check what a run would do without sending anything:
#   boundarycheck preflight --config boundarycheck.yaml
# then run it with the acknowledgement:   boundarycheck test ... --transport live --ack-authorization
# Design and limits: docs/remote-live-design.md
"""
_LOOPBACK_SCOPE = """\
scope:
  id: my-first-check                      # names this assessment in every report
  target:
    label: my-service
    base_url: http://127.0.0.1:8000       # loopback only in v0.1
    request_budget: 500                   # hard stop on requests per run
    rate_limit_rps: 10
"""
_REMOTE_SCOPE = """\
scope:
  id: my-assessment                       # names this assessment in every report
  target:
    label: my-service
    base_url: https://api.staging.example.test    # EDIT: the ONE host this run may talk to (https only)
    allowed_hosts: [api.staging.example.test]     # EDIT: the same host again (add :port if it is not 443)
    # allowed_networks: [10.20.0.0/16]            # only if the target is on a private network you reach by VPN
    # ca_bundle: ./client-ca.pem                  # only if the target uses a private certificate authority
    request_budget: 500                   # hard stop on requests per run
    rate_limit_rps: 2                     # at most 20 for a remote host
  authorization:                          # YOUR declaration; the tool cannot verify it
    engagement: "EDIT: your reference (a statement of work or a ticket)"
    not_after: 1970-01-01T00:00:00Z       # EDIT: when the engagement ends. This placeholder is already past,
                                          # so the template cannot run until you set a real, near date
"""
if _LOOPBACK_HEADER not in STARTER_CONFIG or _LOOPBACK_SCOPE not in STARTER_CONFIG:
    raise RuntimeError("the starter template changed: update the remote variant")
REMOTE_CONFIG = STARTER_CONFIG.replace(_LOOPBACK_HEADER, _REMOTE_HEADER).replace(_LOOPBACK_SCOPE, _REMOTE_SCOPE)
