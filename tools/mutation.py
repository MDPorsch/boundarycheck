"""Mutation check: does the test suite notice a deliberate security bug?

    uv run python tools/mutation.py                 # baseline, then every mutant
    uv run python tools/mutation.py NAME [NAME...]  # only the named mutants

The repo is copied to a scratch directory and ONE bug is injected into the copy at a time (the real
tree is never modified). A mutant is KILLED when at least one test fails, SURVIVED when every test
still passes, NOAPPLY when the patch no longer matches the source (the table is stale). The unmutated
baseline must be green first: a red baseline would make every mutant look killed for the wrong reason.

Exit status: 0 when every mutant is killed, 1 when one survived, 2 when one did not apply or the
baseline is not green.

Known limits: killing a mutant shows a test notices THAT bug, not that no other bug exists. An
"equivalent" mutant (one that cannot change observable behaviour) can never be killed; none is kept in
this table, and the comments say where two layers guard the same property and so are removed together.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = "src/boundarycheck"
CFG, ORC, CMP, ENG, RED, EVI, LIV, LAB, REP, NET, MOD, CLI = (
    f"{SRC}/{n}.py"
    for n in ("config", "oracle", "comparator", "engine", "redact", "evidence", "transports/live", "transports/lab_fixture", "report", "netcheck", "model", "cli")
)  # fmt: skip

M: dict[str, list[tuple[str, str, str]]] = {
    # ---- the config loader ---------------------------------------------------------------------
    # an alias event also carries an anchor name, so each check alone still refuses an alias (two layers): remove both
    "yaml_aliases_and_anchors_allowed": [(CFG, "if self.check_event(yaml.events.AliasEvent):", "if False:"), (CFG, 'if getattr(self.peek_event(), "anchor", None) is not None:', "if False:")],
    "yaml_anchors_allowed": [(CFG, 'if getattr(self.peek_event(), "anchor", None) is not None:', "if False:")],
    "yaml_duplicate_keys_allowed": [(CFG, "if key in seen:", "if False:")],
    "yaml_merge_keys_allowed": [(CFG, 'if key_node.tag == "tag:yaml.org,2002:merge":', "if False:")],
    "yaml_depth_unlimited": [(CFG, "if self._depth > MAX_DEPTH:", "if False:")],
    # two layers guard the size cap (a stat before reading, a length check after): remove both
    "config_size_cap_ignored": [(CFG, "if len(raw) > MAX_CONFIG_BYTES:", "if False:"), (CFG, "if target.stat().st_size > MAX_CONFIG_BYTES:", "if False:")],
    "config_unknown_keys_allowed": [(CFG, 'extra="forbid"', 'extra="ignore"')],
    "config_type_coercion_allowed": [(CFG, "strict=True,", "strict=False,")],
    "config_remote_host_allowed": [(CFG, "                parse_loopback_base_url(value)", "                pass")],
    "config_write_methods_allowed": [(CFG, 'method: Literal["GET", "HEAD"]', 'method: Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]')],
    "config_dot_segments_allowed": [(CFG, 'if any(part in {".", ".."} for part in value.split("/")):', "if False:")],
    "config_path_not_checked_whole": [(CFG, "_PATH_RE.fullmatch(value)", "_PATH_RE.match(value)")],
    "config_identifier_pattern_weakened": [(CFG, 'IDENT_PATTERN: Final = r"^[A-Za-z0-9_-][A-Za-z0-9._~-]{0,127}$"', 'IDENT_PATTERN: Final = r"^.{1,128}$"')],
    "config_env_pattern_weakened": [(CFG, 'ENV_PATTERN: Final = r"^[A-Z_][A-Z0-9_]{0,63}$"', 'ENV_PATTERN: Final = r"^.{1,64}$"')],
    "config_empty_credential_allowed": [(CFG, "if self.env is None and self.fixture is None:", "if False:")],
    "config_anonymous_not_reserved": [(CFG, "if ANONYMOUS in cfg.principals:", "if False:")],
    "config_unknown_principal_allowed": [(CFG, "if m.principal not in cfg.principals:", "if False:")],
    "config_missing_capability_allowed": [(CFG, "if a.cap not in cfg.policy.capabilities:", "if False:")],
    "config_missing_surface_allowed": [(CFG, "if a.surface not in cfg.policy.fields:", "if False:")],
    # ---- the netcheck rules --------------------------------------------------------------------
    "net_ipv4_mapped_trusted": [(NET, "    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:\n        return False", "    pass")],
    "net_userinfo_allowed": [(NET, "if parts.username is not None or parts.password is not None:", "if False:")],
    "net_https_allowed": [(NET, 'if parts.scheme != "http":', "if False:")],
    "net_path_allowed": [(NET, 'if parts.query or parts.fragment or parts.path not in ("", "/"):', "if False:")],
    # ---- the oracle ----------------------------------------------------------------------------
    "oracle_inactive_principal_allowed": [(ORC, 'if self._cfg.principals[principal].status != "active":', "if False:")],
    "oracle_revoked_membership_counts": [(ORC, 'for m in config.memberships if m.status == "active"}', "for m in config.memberships}")],
    "oracle_suspended_tenant_ignored": [(ORC, 'if tenant.state != "active":', "if False:")],
    "oracle_scope_ignored": [(ORC, "if not self._in_scope(resource.tenant, resource):", "if False:")],
    "oracle_role_check_ignored": [(ORC, "if role not in self._cfg.policy.capabilities.get(action.cap, []):", "if False:")],
    "oracle_hidden_always_not_found": [(ORC, "return Outcome.DENY_NOT_FOUND if self._cfg.policy.hidden_is_not_found else Outcome.DENY_FORBIDDEN", "return Outcome.DENY_NOT_FOUND")],
    "oracle_field_floor_ignored": [(ORC, "if self._rank[role] >= self._rank[minimum]", "if True")],
    "oracle_list_scope_ignored": [(ORC, "and self._in_scope(resource.tenant, r)", "and True")],
    # ---- the comparator ------------------------------------------------------------------------
    "cmp_unmapped_status_is_a_decision": [(CMP, "}.get(status)", "}.get(status, Outcome.DENY_NOT_FOUND)")],
    "cmp_fields_not_checked": [(CMP, "leaked = _exposed(set(paths(doc)), visible)", "leaked = []")],
    "cmp_item_fields_not_checked": [(CMP, 'leaked = _exposed({p for i in items for p in paths(i)}, visible, "items[].")', "leaked = []")],
    "cmp_envelope_not_checked": [(CMP, "        if extra:", "        if False:")],
    "cmp_list_leak_not_checked": [(CMP, 'leaked = [f"{known[i]} ({i})" for i in ids if isinstance(i, str) and i in known and i not in visible]', "leaked = []")],
    "cmp_list_total_not_checked": [(CMP, "if spec.total_field is not None and total != len(visible):", "if False:")],
    "cmp_non_json_allow_is_clean": [(CMP, '            Status.INCONCLUSIVE,\n            "allow",\n            "the response body is not JSON,', '            Status.NO_ISSUE_OBSERVED,\n            "allow",\n            "the response body is not JSON,')],
    "cmp_transport_error_is_clean": [(CMP, "    if observation.error is not None:", "    if False:")],
    "cmp_redirect_is_not_refused": [(CMP, 'if observation.error == "redirect":', "if False:")],
    "cmp_existence_oracle_not_flagged": [(CMP, "if exp.outcome is Outcome.DENY_NOT_FOUND and observed is Outcome.DENY_FORBIDDEN:", "if False:")],
    "cmp_signature_ignores_status": [(CMP, 'parts = {"status": str(observation.status), "body": body}', 'parts = {"body": body}')],
    "cmp_signature_ignores_body": [(CMP, '"body": body}', '"body": ""}')],
    "cmp_signature_ignores_headers": [(CMP, 'SIGNATURE_HEADERS = ("content-type", "cache-control", "www-authenticate")', "SIGNATURE_HEADERS = ()")],
    "cmp_signature_ignores_nothing": [(CMP, "if k not in ignore}", "}")],
    # ---- the engine ----------------------------------------------------------------------------
    "eng_missing_credential_still_sent": [(ENG, "if not transport.has_credential(case.principal):", "if False:")],
    "eng_request_budget_ignored": [(ENG, "if sent >= budget:", "if False:")],
    "eng_egress_violation_does_not_abort": [(ENG, "            aborted = True", "            aborted = False")],
    "eng_transport_error_is_clean": [(ENG, '_result(case, Status.ERROR, f"transport error', '_result(case, Status.NO_ISSUE_OBSERVED, f"transport error')],
    "eng_leak_guard_removed": [(ENG, "            assert_no_secrets([text], transport.secrets())", "            pass")],
    "eng_concealment_differences_ignored": [(ENG, "    if diff:\n", "    if False:\n")],
    "eng_concealment_unusable_peer_is_clean": [(ENG, "    for wanted in _PRIORITY:", "    for wanted in ():")],
    "model_finding_does_not_win_exit_code": [(MOD, "    if any(s is Status.FINDING_CANDIDATE for s in seen):\n        return 1\n", "")],
    "model_any_clean_case_exits_zero": [(MOD, "if seen and all(s is Status.NO_ISSUE_OBSERVED for s in seen):", "if any(s is Status.NO_ISSUE_OBSERVED for s in seen):")],
    "model_empty_run_exits_zero": [(MOD, "if seen and all(s is Status.NO_ISSUE_OBSERVED for s in seen):", "if all(s is Status.NO_ISSUE_OBSERVED for s in seen):")],
    # ---- redaction -----------------------------------------------------------------------------
    "red_jwt_not_redacted": [(RED, 'value = _JWT.sub("[redacted-jwt]", value)', "pass")],
    "red_email_not_redacted": [(RED, 'value = _EMAIL.sub("[redacted-email]", value)', "pass")],
    "red_long_strings_kept": [(RED, "        return _LONG.sub(", "        return value or _LONG.sub(")],
    "red_exact_secret_kept": [(RED, '            value = value.replace(secret, "[credential]")', "            pass")],
    "red_sensitive_header_kept": [(RED, 'name: "[redacted]" if name.lower() in SENSITIVE_HEADERS else self.text(value)', "name: self.text(value)")],
    "red_cookie_header_kept": [(RED, 'SENSITIVE_HEADERS: Final = frozenset({"authorization", "proxy-authorization", "cookie", "set-cookie"})', 'SENSITIVE_HEADERS: Final = frozenset({"authorization", "proxy-authorization"})')],
    "red_mask_fields_ignored": [(RED, '"[masked]" if k in self._mask else self._walk(v)', "self._walk(v)")],
    "red_mask_not_applied_in_lists": [(RED, "            return [self._walk(v) for v in value]", "            return value")],
    "red_leak_guard_disabled": [(RED, "    if any(n in t for n in needles for t in haystack):", "    if False:")],
    "red_tiny_secrets_not_ignored": [(RED, "MIN_SECRET_LENGTH: Final = 8", "MIN_SECRET_LENGTH: Final = 1")],
    "red_blob_not_bounded": [(RED, '"body": body[:BLOB_BODY_LIMIT],', '"body": body,')],
    # ---- the run store -------------------------------------------------------------------------
    "evi_world_writable_dir_allowed": [(EVI, "if self.root.stat().st_mode & stat.S_IWOTH:", "if False:")],
    "evi_symlinked_root_allowed": [(EVI, "if self.root.is_symlink():", "if False:")],
    "evi_files_world_readable": [(EVI, "os.O_EXCL, 0o600)", "os.O_EXCL, 0o644)")],
    "evi_run_dir_world_readable": [(EVI, "run_dir.mkdir(mode=0o700)", "run_dir.mkdir(mode=0o755)")],
    "evi_run_id_not_validated": [(EVI, "_RUN_ID = re.compile(r\"^(\\d{8}T\\d{6}Z)-[0-9a-f]{8}$\")", '_RUN_ID = re.compile(r"^(.*)$")')],
    "evi_run_id_not_checked_whole": [(EVI, "    return bool(_RUN_ID.fullmatch(run_id))", "    return bool(_RUN_ID.match(run_id))")],
    "evi_purge_follows_symlinks": [(EVI, "if valid_run_id(p.name) and p.is_dir() and not p.is_symlink()", "if valid_run_id(p.name) and p.is_dir()")],
    "evi_purge_deletes_everything": [(EVI, "if _run_time(path.name) < cutoff:", "if True:")],
    "evi_secrets_not_checked_before_writing": [(EVI, "        assert_no_secrets([json_text, md_text, *blobs.values()], list(secrets))  # before anything exists", "        pass")],
    "evi_age_zero_allowed": [(EVI, "or int(match.group(1)) == 0", "or False")],
    # ---- the live transport --------------------------------------------------------------------
    "live_proxy_environment_trusted": [(LIV, "trust_env=False,", "trust_env=True,")],
    "live_redirects_followed": [(LIV, "follow_redirects=False,", "follow_redirects=True,")],
    "live_write_methods_allowed": [(LIV, 'READ_METHODS: Final = frozenset({"GET", "HEAD"})', 'READ_METHODS: Final = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"})')],
    "live_path_not_validated": [(LIV, "        if not valid_path(path):", "        if False:")],
    "live_path_not_checked_whole": [(LIV, "bool(_PATH.fullmatch(path))", "bool(_PATH.match(path))")],
    "live_peer_not_verified": [(LIV, "            verify_peer(response, self._ip)", "            pass")],
    "live_peer_address_not_compared": [(LIV, "if ipaddress.ip_address(peer) != ipaddress.ip_address(expected_ip):", "if False:")],
    "live_mixed_resolution_accepted": [(LIV, "not all(is_loopback_ip(a) for a in addresses)", "not any(is_loopback_ip(a) for a in addresses)")],
    "live_name_not_checked_at_all": [(LIV, "        if not addresses or not all(is_loopback_ip(a) for a in addresses):", "        if False:")],
    # the raw-size check and the decoded-size check guard overlapping cases: remove both
    "live_body_cap_removed": [(LIV, "        if raw_total > cap:\n            raise _TooLarge", "        if False:\n            raise _TooLarge"), (LIV, "        if len(out) > cap:\n            raise _TooLarge", "        if False:\n            raise _TooLarge")],
    "live_total_timeout_removed": [(LIV, "async with asyncio.timeout(self._timeout):", "async with asyncio.timeout(None):")],
    "live_cookies_replayed": [(LIV, "            self._client.cookies.clear()  # never replay a cookie the target set", "            pass")],
    "live_credential_charset_not_checked": [(LIV, "if v in environ and _TOKEN.fullmatch(environ[v])}", "if v in environ and environ[v]}")],
    "live_credential_not_checked_whole": [(LIV, "_TOKEN.fullmatch(environ[v])", "_TOKEN.match(environ[v])")],
    "live_rate_limit_ignored": [(LIV, "        if slot > now:", "        if False:")],
    "live_unknown_encoding_accepted": [(LIV, "    else:\n        raise _Unreadable\n    out = bytearray()", "    else:\n        decoder = None\n    out = bytearray()")],
    # ---- the lab adapter, reports and CLI ------------------------------------------------------
    "lab_flaws_on_the_patched_variant": [(LAB, 'if chosen and variant != "vulnerable":', "if False:")],
    "lab_unknown_flaws_accepted": [(LAB, "    if unknown:", "    if False:")],
    "report_markdown_not_escaped": [(REP, r'    return _MD_SPECIAL.sub(r"\\\1", _CONTROL.sub(" ", str(value)))[:300]', "    return str(value)[:300]")],
    "report_markdown_control_characters_kept": [(REP, '_CONTROL.sub(" ", str(value))', "str(value)")],
    "cli_failures_exit_one": [(CLI, "    raise typer.Exit(2)\n\n\ndef _version", "    raise typer.Exit(1)\n\n\ndef _version")],
    "cli_internal_errors_exit_one": [(CLI, '_fail(f"internal error', 'typer.echo(f"internal error'), ],
}  # fmt: skip

IGNORE = shutil.ignore_patterns(
    ".venv",
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "dist",
    "out",
    ".boundarycheck",
    "lab",
)
TEST_PATHS = [
    "tests/unit",
    "tests/negative",
    "tests/integration",
]  # fastest-failing first; packaging is slow and unrelated


def run_one(work: Path, edits: list[tuple[str, str, str]]) -> tuple[str, str]:
    if work.exists():
        shutil.rmtree(work)
    shutil.copytree(REPO, work, ignore=IGNORE)
    (work / "lab").symlink_to(REPO / "lab")  # the reference target is read-only input
    for relative, old, new in edits:
        path = work / relative
        text = path.read_text(encoding="utf-8")
        if old not in text:
            return "NOAPPLY", f"pattern not found in {relative}: {old[:60]!r}"
        path.write_text(text.replace(old, new, 1), encoding="utf-8")
    env = dict(os.environ, PYTHONPATH=f"{work / 'src'}:{work}", BOUNDARYCHECK_MUTATION="1")
    imported = subprocess.run(
        [sys.executable, "-c", "import boundarycheck; print(boundarycheck.__file__)"],
        capture_output=True, text=True, env=env, cwd=work, check=False,
    ).stdout.strip()  # fmt: skip
    if not imported.startswith(str(work)):
        return "NOAPPLY", f"the scratch copy is not the imported package: {imported}"
    result = subprocess.run(
        [sys.executable, "-m", "pytest", *TEST_PATHS, "-q", "--tb=no", "-x", "-p", "no:cacheprovider", "--no-header"],
        cwd=work, env=env, capture_output=True, text=True, timeout=900, check=False,
    )  # fmt: skip
    tail = (result.stdout.strip().splitlines() or [result.stderr[-200:]])[-1]
    return ("KILLED" if result.returncode != 0 else "SURVIVED"), tail


def main(names: list[str]) -> int:
    chosen = {n: M[n] for n in names} if names else M
    unknown = [n for n in names if n not in M]
    if unknown:
        print(f"unknown mutant(s): {unknown}")
        return 2
    counts = {"KILLED": 0, "SURVIVED": 0, "NOAPPLY": 0}
    with tempfile.TemporaryDirectory(prefix="boundarycheck-mutation-") as scratch:
        verdict, info = run_one(Path(scratch) / "work", [])
        if verdict != "SURVIVED":  # "SURVIVED" with no edits means nothing failed: the baseline is green
            print(f"BASELINE NOT GREEN ({verdict}): {info}\nrefusing to run mutants")
            return 2
        print(f"baseline green | {info}", flush=True)
        for name, edits in chosen.items():
            verdict, info = run_one(Path(scratch) / "work", edits)
            counts[verdict] += 1
            print(f"{verdict:9} {name} | {info}", flush=True)
    print(
        f"\nTOTAL {len(chosen)}  killed {counts['KILLED']}  survived {counts['SURVIVED']}  noapply {counts['NOAPPLY']}"
    )
    if counts["NOAPPLY"]:
        return 2
    return 1 if counts["SURVIVED"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
