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

AUZ, TPL = f"{SRC}/authorization.py", f"{SRC}/template.py"
CRD, KCH, SAR, OAI = (f"{SRC}/{n}.py" for n in ("credentials", "keychain", "sarif", "openapi"))
PLN, STD, SQS = f"{SRC}/planner.py", f"{SRC}/statediff.py", f"{SRC}/transports/sqlite_state.py"

M: dict[str, list[tuple[str, str, str]]] = {
    # ---- the config loader ---------------------------------------------------------------------
    # an alias event also carries an anchor name, so each check alone still refuses an alias (two layers): remove both
    "yaml_aliases_and_anchors_allowed": [(CFG, "if self.check_event(yaml.events.AliasEvent):", "if False:"), (CFG, 'if getattr(self.peek_event(), "anchor", None) is not None:', "if False:")],
    "yaml_anchors_allowed": [(CFG, 'if getattr(self.peek_event(), "anchor", None) is not None:', "if False:")],
    "yaml_duplicate_keys_allowed": [(CFG, "if key in seen:", "if False:")],
    "yaml_merge_keys_allowed": [(CFG, 'if key_node.tag == "tag:yaml.org,2002:merge":', "if False:")],
    "yaml_depth_unlimited": [(CFG, "if self._depth > self.max_depth:", "if False:")],
    # two layers guard the size cap (a stat before reading, a length check after): remove both
    "config_size_cap_ignored": [(CFG, "if len(raw) > MAX_CONFIG_BYTES:", "if False:"), (CFG, "if target.stat().st_size > MAX_CONFIG_BYTES:", "if False:")],
    "config_unknown_keys_allowed": [(CFG, 'extra="forbid"', 'extra="ignore"')],
    "config_type_coercion_allowed": [(CFG, "strict=True,", "strict=False,")],
    "config_dot_segments_allowed": [(CFG, 'if any(part in {".", ".."} for part in value.split("/")):', "if False:")],
    "config_path_not_checked_whole": [(CFG, "_PATH_RE.fullmatch(value)", "_PATH_RE.match(value)")],
    "config_identifier_pattern_weakened": [(CFG, 'IDENT_PATTERN: Final = r"^[A-Za-z0-9_-][A-Za-z0-9._~-]{0,127}$"', 'IDENT_PATTERN: Final = r"^.{1,128}$"')],
    "config_env_pattern_weakened": [(CFG, 'ENV_PATTERN: Final = r"^[A-Z_][A-Z0-9_]{0,63}$"', 'ENV_PATTERN: Final = r"^.{1,64}$"')],
    "config_empty_credential_allowed": [(CFG, "if self.env is None and self.fixture is None and self.keychain is None:", "if False:")],
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
    "evi_secrets_not_checked_before_writing": [(EVI, '        assert_no_secrets([json_text, md_text, sarif or "", *blobs.values()], list(secrets))  # before anything exists', "        pass")],
    "evi_age_zero_allowed": [(EVI, "or int(match.group(1)) == 0", "or False")],
    # ---- the live transport --------------------------------------------------------------------
    "live_proxy_environment_trusted": [(LIV, "trust_env=False,", "trust_env=True,")],
    "live_redirects_followed": [(LIV, "follow_redirects=False,", "follow_redirects=True,")],
    "live_write_methods_allowed": [(LIV, 'READ_METHODS: Final = frozenset({"GET", "HEAD"})', 'READ_METHODS: Final = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"})')],
    "live_path_not_validated": [(LIV, "        if not valid_path(path):", "        if False:")],
    "live_path_not_checked_whole": [(LIV, "bool(_PATH.fullmatch(path))", "bool(_PATH.match(path))")],
    "live_peer_not_verified": [(LIV, "            verify_peer(response, self._ip)", "            pass")],
    "live_peer_address_not_compared": [(LIV, "if ipaddress.ip_address(peer) != ipaddress.ip_address(expected_ip):", "if False:")],
    # the raw-size check and the decoded-size check guard overlapping cases: remove both
    "live_body_cap_removed": [(LIV, "        if raw_total > cap:\n            raise _TooLarge", "        if False:\n            raise _TooLarge"), (LIV, "        if len(out) > cap:\n            raise _TooLarge", "        if False:\n            raise _TooLarge")],
    "live_total_timeout_removed": [(LIV, "async with asyncio.timeout(self._timeout):", "async with asyncio.timeout(None):")],
    "live_cookies_replayed": [(LIV, "            self._client.cookies.clear()  # never replay a cookie the target set", "            pass")],
    "live_credential_charset_not_checked": [(CRD, "        return pattern.fullmatch(self.value) is not None", "        return bool(self.value)")],
    "live_credential_not_checked_whole": [(CRD, "        return pattern.fullmatch(self.value) is not None", "        return pattern.match(self.value) is not None")],
    "live_rate_limit_ignored": [(LIV, "        if slot > now:", "        if False:")],
    "live_unknown_encoding_accepted": [(LIV, "    else:\n        raise _Unreadable\n    out = bytearray()", "    else:\n        decoder = None\n    out = bytearray()")],
    # ---- the lab adapter, reports and CLI ------------------------------------------------------
    "lab_flaws_on_the_patched_variant": [(LAB, 'if chosen and variant != "vulnerable":', "if False:")],
    "lab_unknown_flaws_accepted": [(LAB, "    if unknown:", "    if False:")],
    "report_markdown_not_escaped": [(REP, r'    return _MD_SPECIAL.sub(r"\\\1", _CONTROL.sub(" ", str(value)))[:300]', "    return str(value)[:300]")],
    "report_markdown_control_characters_kept": [(REP, '_CONTROL.sub(" ", str(value))', "str(value)")],
    "cli_failures_exit_one": [(CLI, "    raise typer.Exit(2)\n\n\ndef _version", "    raise typer.Exit(1)\n\n\ndef _version")],
    "cli_internal_errors_exit_one": [(CLI, '_fail(f"internal error', 'typer.echo(f"internal error'), ],
    # ---- M4: write checks and the state diff (docs/contract.md s9) -------------------------------
    "planner_sends_writes_the_policy_allows": [(PLN, "                if action.is_write and expected.outcome is Outcome.ALLOW:\n                    continue  # a write the policy allows is never sent (docs/contract.md s9.2)\n", "")],
    "planner_counts_no_unexercised_writes": [(PLN, "        and oracle.expected_for(principal, action, resource).outcome is Outcome.ALLOW\n    )\n", "        and False\n    )\n")],
    "diff_ignores_removed_rows": [(STD, '        changes.extend(StateChange(table, key, "removed") for key in old.keys() - new.keys())\n', "")],
    "diff_ignores_added_rows": [(STD, '        changes.extend(StateChange(table, key, "added") for key in new.keys() - old.keys())\n', "")],
    "diff_ignores_modified_rows": [(STD, "if old[key] != new[key])", "if False)")],
    "diff_accepts_different_table_sets": [(STD, "    if set(before) != set(after):", "    if False:")],
    "diff_key_is_not_text": [(STD, "    old = {str(row[0]): row for row in before[table]}", "    old = {row[0]: row for row in before[table]}")],
    "diff_is_not_sorted": [(STD, "    return sorted(changes)", "    return changes")],
    "diff_looks_at_the_first_table_only": [(STD, "    for table in sorted(before):", "    for table in sorted(before)[:1]:")],
    "snapshot_includes_the_audit_table": [(SQS, 'EXCLUDED_TABLES: Final = frozenset({"audit_events", "alembic_version"})', "EXCLUDED_TABLES: Final = frozenset()")],
    "snapshot_rows_are_unordered": [(SQS, "ORDER BY 1", "")],
    "snapshot_of_a_missing_file_is_empty": [(SQS, '        raise SnapshotError("the database file to snapshot does not exist")', "        return {}")],
    "snapshot_does_not_quote_table_names": [(SQS, """quoted = '"' + name.replace('"', '""') + '"'""", "quoted = name")],
    "write_state_change_ignored": [(CMP, "    if not changes:\n        return verdict\n", "    if True:\n        return verdict\n")],
    "write_2xx_range_too_wide": [(CMP, "    if status is not None and 200 <= status < 300:\n        # access was granted", "    if status is not None and 200 <= status < 600:\n        # access was granted")],
    "write_mutation_severity_downgraded": [(CMP, '        MUTATION_RULE,\n        "high",\n        "high",\n', '        MUTATION_RULE,\n        "medium",\n        "medium",\n')],
    "write_mutation_uses_the_access_rule": [(CMP, '        MUTATION_RULE,\n        "high",', '        case.rule_id,\n        "high",')],
    "write_failure_with_a_change_is_not_a_finding": [(CMP, "    if status is not None and 200 <= status < 300:\n        # access was granted", "    if status is None or 200 <= status < 300:\n        # access was granted")],
    "engine_never_restores_state": [(ENG, "        await transport.reset_state()\n        restored = await transport.snapshot()\n", "        restored = await transport.snapshot()\n")],
    "engine_does_not_verify_the_restore": [(ENG, '    if diff(baseline, restored):\n        return changes, "the pristine state was not restored; the remaining write checks were not run"\n', "")],
    "engine_sends_writes_to_a_transport_without_state": [(ENG, "        if is_write and not state_aware:\n            results[case.key] = _result(case, Status.NOT_RUN, NO_STATE, when)\n            continue\n", "")],
    "engine_ignores_reads_only": [(ENG, "    cases = [c for c in planned if not (reads_only and c.action.is_write)]", "    cases = list(planned)")],
    "engine_forgets_that_writes_were_halted": [(ENG, "        if is_write and halted is not None:\n            results[case.key] = _result(case, Status.NOT_RUN, halted, when)\n            continue\n", "")],
    "engine_takes_no_baseline": [(ENG, "            baseline = await stateful.snapshot()", "            baseline = {}")],
    "engine_does_not_send_the_body": [(ENG, '    return json.dumps(case.action.body, sort_keys=True, separators=(",", ":")).encode("utf-8")', "    return None")],
    "engine_concealment_includes_writes": [(ENG, "            case.action.is_write\n            or case.principal is None", "            case.principal is None")],
    "engine_does_not_record_state_changes": [(ENG, "        result.state_changes = [c.as_dict() for c in changes]\n        try:", "        try:")],
    "engine_failed_request_that_wrote_is_only_an_error": [(ENG, "            if changes:  # the request failed, yet state changed: that is still a finding", "            if False:")],
    "engine_does_not_disclose_unexercised_writes": [(ENG, "    elif unexercised_writes(config):", "    elif False:")],
    "engine_does_not_disclose_reads_only": [(ENG, "    if omitted:\n        limitations.append(", "    if False:\n        limitations.append(")],
    "engine_ignores_a_failed_snapshot": [(ENG, '        return [], "the state snapshot after the request failed; the remaining write checks were not run"', "        return [], None")],
    "lab_fixture_is_not_state_aware": [(LAB, "    state_aware = True\n\n    def __init__", "    state_aware = False\n\n    def __init__")],
    "lab_fixture_reset_restores_nothing": [(LAB, "                    source.backup(target)\n", "                    pass\n")],
    "lab_fixture_accepts_a_body_on_a_read": [(LAB, '        if body is not None and method not in WRITE_METHODS:\n            raise PolicyRefusal("a request body is only allowed on a write")\n', "")],
    "lab_fixture_sends_no_body": [(LAB, "content=body)", "content=None)")],
    "lab_fixture_accepts_unknown_methods": [(LAB, '        if method not in (*READ_METHODS, *WRITE_METHODS):\n            raise PolicyRefusal(f"method {method[:10]!r} is not allowed")\n', "")],
    "live_accepts_a_request_body": [(LIV, '        if body is not None:\n            raise PolicyRefusal("the live transport never sends a request body")\n', "")],
    "config_allows_a_body_on_a_read": [(CFG, "        if self.body is not None and not self.is_write:", "        if False:")],
    "config_body_size_unlimited": [(CFG, '        if len(encoded.encode("utf-8")) > MAX_BODY_BYTES:', "        if False:")],
    "config_body_depth_unlimited": [(CFG, "        if _depth(value) > MAX_BODY_DEPTH:", "        if False:")],
    "config_body_need_not_be_json": [(CFG, '            encoded = json.dumps(value, separators=(",", ":"))', "            encoded = str(value)")],
    "config_nothing_is_a_write": [(CFG, "        return self.method in WRITE_METHODS", "        return False")],
    "config_delete_is_not_a_write": [(CFG, 'WRITE_METHODS: Final = ("POST", "PUT", "PATCH", "DELETE")', 'WRITE_METHODS: Final = ("POST", "PUT", "PATCH")')],
    "cli_fixture_ignores_reads_only": [(CLI, "            _run_fixture(cfg, fixture_variant, flaws, reads_only)", "            _run_fixture(cfg, fixture_variant, flaws, False)")],
    "cli_live_ignores_reads_only": [(CLI, "            else _run_live(cfg, reads_only)", "            else _run_live(cfg, False)")],
    "cli_plan_echoes_the_body": [(CLI, "            body = f\" [JSON body, {len(json.dumps(c.action.body, separators=(',', ':')))} bytes]\"", "            body = f\" {c.action.body}\"")],
    "cli_hides_the_notes": [(CLI, '        if "--reads-only" in note or "not exercised" in note:', "        if False:")],
    "report_drops_the_state_changes": [(REP, '        "state_changes": [dict(change) for change in c.state_changes],\n', "")],
    # ---- remote live mode (docs/remote-live-design.md) -------------------------------------------
    "config_remote_needs_no_allowed_hosts": [(CFG, "        if len(self.allowed_hosts) != 1:", "        if False:")],
    "config_allowed_host_may_differ_from_the_url": [(CFG, "        if (declared_host, declared_port) != (host, port):", "        if False:")],
    "config_allowed_host_accepts_wildcards_and_capitals": [(CFG, "(?P<host>[a-z0-9](?:", "(?P<host>[A-Za-z0-9*](?:")],
    "config_ip_literal_host_not_judged": [(CFG, "                check_address(host, self.allowed_networks)", "                pass")],
    "config_remote_rate_not_capped": [(CFG, '        if "rate_limit_rps" in self.model_fields_set and self.rate_limit_rps > REMOTE_MAX_RPS:', "        if False:")],
    "config_remote_default_rate_not_lowered": [(CFG, '        if self.is_remote and "rate_limit_rps" not in self.model_fields_set:\n            return REMOTE_DEFAULT_RPS', '        if False:\n            return REMOTE_DEFAULT_RPS')],
    "config_remote_needs_no_authorization": [(CFG, "        if self.target.is_remote and self.authorization is None:", "        if False:")],
    "config_window_may_be_reversed": [(CFG, "            if self.not_before >= self.not_after:", "            if False:")],
    "config_window_may_be_endless": [(CFG, "            if self.not_after - self.not_before > timedelta(days=MAX_WINDOW_DAYS):", "            if False:")],
    "config_naive_timestamps_accepted": [(CFG, "        if value is not None and value.tzinfo is None:", "        if False:")],
    "config_engagement_may_hold_control_characters": [(CFG, '    if any(unicodedata.category(ch) in {"Cc", "Cf", "Zl", "Zp"} for ch in value):', "    if False:")],
    "net_never_ranges_not_enforced": [(NET, '    if why is not None:\n        raise AddressRefused(f"{address} is never allowed: {why}")\n', "")],
    "net_public_addresses_need_listing": [(NET, "    if address.is_global:\n        return\n", "    if False:\n        return\n")],
    "net_any_private_address_accepted": [(NET, "        if address.version == net.version and address in net:", "        if True:")],
    "net_zone_ids_accepted": [(NET, '    if "%" in text:\n        raise AddressRefused("an IP address with a zone id is never accepted")\n', "")],
    "net_ipv6_loopback_never_allowed": [(NET, "    if address == _IPV6_LOOPBACK:\n        return None  # ::1 sits inside ::/96 but is ordinary loopback: it needs listing like 127.0.0.1\n", "")],
    "net_listed_range_may_include_never_ranges": [(NET, "            if net.version == never.version and net.overlaps(never):", "            if False:")],
    "net_listed_ranges_not_capped": [(NET, "    if len(networks) > MAX_NETWORKS:", "    if False:")],
    "net_listed_range_needs_no_prefix": [(NET, '        if "/" not in text or "%" in text:', '        if "%" in text:')],
    "net_listed_range_may_have_host_bits": [(NET, "ipaddress.ip_network(text, strict=True)", "ipaddress.ip_network(text, strict=False)")],
    "net_remote_may_be_http": [(NET, '    if parts.scheme != "https":\n        raise NotLoopback(f"base_url must use https:// for any host that is not loopback; {V0_2_HINT}")\n', "")],
    "net_loopback_may_be_https": [(NET, '        if parts.scheme != "http":\n            raise NotLoopback("a loopback base_url must use http://")\n', "")],
    "net_user_info_accepted": [(NET, "    if parts.username is not None or parts.password is not None:", "    if False:")],
    "net_path_query_fragment_accepted": [(NET, '    if parts.query or parts.fragment or parts.path not in ("", "/"):', "    if False:")],
    "live_peer_policy_not_applied": [(LIV, '        (policy or EgressPolicy.loopback("", 0)).check(peer)', "        pass")],
    "live_tls_not_verified": [(LIV, "    context = ssl.create_default_context()\n", "    context = ssl.create_default_context()\n    context.check_hostname = False\n    context.verify_mode = ssl.CERT_NONE\n")],
    "live_tls_host_name_not_checked": [(LIV, "    context = ssl.create_default_context()\n", "    context = ssl.create_default_context()\n    context.check_hostname = False\n")],
    "live_ca_bundle_ignored": [(LIV, "            context.load_verify_locations(cafile=str(ca_bundle))", "            pass")],
    "live_sni_not_the_declared_name": [(LIV, '            extensions["sni_hostname"] = self._host  # the certificate is checked against THIS name', "            pass")],
    "live_address_literal_not_judged": [(LIV, "                policy.check(host)\n", "                pass\n")],
    "live_remote_answers_not_judged": [(LIV, "                policy.check(address)\n", "                pass\n")],
    "live_only_the_first_answer_judged": [(LIV, "        for address in addresses:\n", "        for address in addresses[:1]:\n")],
    "live_empty_answer_accepted": [(LIV, '        if not addresses:\n            raise EgressViolation("the host name did not resolve to any address")\n', "")],
    "live_default_port_kept_in_host_header": [(LIV, "        self._host_header = shown if (egress.is_remote and port == 443) else f\"{shown}:{port}\"", "        self._host_header = f\"{shown}:{port}\"")],
    "live_from_config_drops_the_listed_networks": [(LIV, "host=host, port=port, allowed_networks=target.allowed_networks,", "host=host, port=port, allowed_networks=(),")],
    "live_from_config_ignores_the_remote_rate": [(LIV, "rate_limit_rps=target.effective_rate_limit_rps,", "rate_limit_rps=target.rate_limit_rps,")],
    "auth_window_start_ignored": [(AUZ, "    if authorization.not_before is not None and now < authorization.not_before:", "    if False:")],
    "auth_window_end_ignored": [(AUZ, "    if now > authorization.not_after:", "    if False:")],
    "auth_window_length_ignored": [(AUZ, "    if authorization.not_after - now > timedelta(days=MAX_WINDOW_DAYS):", "    if False:")],
    "auth_report_does_not_say_it_cannot_verify": [(AUZ, '        "The tool does not and cannot verify it. "\n', "")],
    "cli_ack_not_required": [(CLI, "    if not acknowledged:", "    if False:")],
    "cli_window_not_checked": [(CLI, "        authorization.check_window(cfg.scope.authorization, datetime.now(UTC))\n    except authorization.AuthorizationError as exc:\n        _fail(str(exc))", "        pass\n    except authorization.AuthorizationError as exc:\n        _fail(str(exc))")],
    "cli_remote_run_without_attestation": [(CLI, "return await run(cfg, transport, reads_only=reads_only, attestation=note)", "return await run(cfg, transport, reads_only=reads_only)")],
    "cli_preflight_ignores_refused_addresses": [(CLI, "    if refused:\n        _fail(", "    if False:\n        _fail(")],
    "cli_init_remote_writes_the_plain_starter": [(CLI, "handle.write(REMOTE_CONFIG if remote else STARTER_CONFIG)", "handle.write(STARTER_CONFIG)")],
    "template_remote_placeholder_is_a_live_window": [(TPL, "not_after: 1970-01-01T00:00:00Z", "not_after: 2099-01-01T00:00:00Z")],
    "engine_ignores_an_explicit_attestation": [(ENG, "        attestation=attestation\n        or (ATTESTATION_FIXTURE if transport.name.startswith(\"fixture\") else ATTESTATION_LIVE),", "        attestation=(ATTESTATION_FIXTURE if transport.name.startswith(\"fixture\") else ATTESTATION_LIVE),")],
    # ---- v0.3: root path, credential schemes, keychain, SARIF, OpenAPI import (docs/design-v0.3.md) --------
    "root_path_is_refused": [(CFG, 'rf"^/(?:{_SEGMENT}(?:/{_SEGMENT})*)?$"', 'rf"^/(?:{_SEGMENT}(?:/{_SEGMENT})*)$"')],
    "cred_header_name_not_checked": [(CFG, "            if HEADER_NAME.fullmatch(self.name) is None:", "            if False:")],
    "cred_forbidden_header_names_allowed": [(CFG, "            if self.name.lower() in FORBIDDEN_HEADERS:", "            if False:")],
    "cred_prefix_not_checked": [(CFG, "            if self.prefix is not None and PREFIX.fullmatch(self.prefix) is None:", "            if False:")],
    "cred_cookie_name_not_checked": [(CFG, "            if COOKIE_NAME.fullmatch(self.name) is None:", "            if False:")],
    "cred_bearer_may_carry_a_name": [(CFG, "            if self.name is not None or self.prefix is not None:", "            if False:")],
    "cred_cookie_may_carry_a_prefix": [(CFG, "            if self.prefix is not None:\n                raise ValueError(\"a cookie credential takes no prefix\")", "            if False:\n                raise ValueError(\"a cookie credential takes no prefix\")")],
    "cred_env_and_keychain_together": [(CFG, "        if self.env is not None and self.keychain is not None:", "        if False:")],
    "cred_fixture_only_may_choose_a_scheme": [(CFG, "        if self.env is None and self.keychain is None:\n            raise ValueError(\"in: header and in: cookie", "        if False:\n            raise ValueError(\"in: header and in: cookie")],
    "cred_short_values_usable": [(CRD, 'SECRET_VALUE: Final = re.compile(r"[\\x21-\\x7e]{8,4096}")', 'SECRET_VALUE: Final = re.compile(r"[\\x21-\\x7e]{1,4096}")')],
    "cred_cookie_value_may_hold_a_semicolon": [(CRD, 'COOKIE_VALUE: Final = re.compile(r"[\\x21\\x23-\\x2b\\x2d-\\x3a\\x3c-\\x5b\\x5d-\\x7e]{8,4096}")', "COOKIE_VALUE: Final = SECRET_VALUE")],
    "cred_every_value_is_usable": [(CRD, "        return pattern.fullmatch(self.value) is not None", "        return True")],
    "cred_cookie_header_without_a_name": [(CRD, '            return "Cookie", f"{self.name}={self.value}"', '            return "Cookie", self.value')],
    "cred_header_prefix_dropped": [(CRD, '            return str(self.name), f"{self.prefix}{self.value}"', "            return str(self.name), self.value")],
    "cred_material_repr_shows_the_value": [(CRD, "    value: str = field(repr=False)", "    value: str")],
    "cred_live_always_sends_bearer": [(LIV, "            name, value = self._materials[principal].header()\n            headers[name] = value", '            headers["Authorization"] = f"Bearer {self._materials[principal].value}"')],
    "cred_live_secrets_not_exposed": [(LIV, "        return [m.value for m in self._materials.values()]", "        return []")],
    "keychain_every_backend_accepted": [(KCH, '    return any(module == name or module.startswith(name + ".") for name in ACCEPTED_BACKEND_MODULES)', "    return True")],
    "keychain_chain_takes_the_first_member": [(KCH, "        if _accepted(candidate):", "        if True:")],
    "keychain_unusable_values_stored": [(KCH, "    if SECRET_VALUE.fullmatch(value) is None:", "    if False:")],
    "keychain_locked_error_echoes_the_backend": [(KCH, "    except lib.errors.KeyringLocked:\n        raise KeychainError(f\"the keychain is locked; unlock it and try again ({action})\") from None", "    except lib.errors.KeyringLocked as exc:\n        raise KeychainError(f\"the keychain is locked {exc}\") from None")],
    "keychain_credentials_never_resolved": [(CRD, "        elif cred.keychain is not None:", "        elif False:")],
    "keychain_problems_are_silent": [(CRD, "                    notes.append(f\"principal '{key}': {exc}\")", "                    pass")],
    "keychain_cli_accepts_a_mismatch": [(CLI, '        if first != typer.prompt("Again (hidden)", hide_input=True):', "        if False:")],
    "sarif_low_severity_is_an_error": [(SAR, '"low": "note"}', '"low": "error"}')],
    "sarif_results_include_every_unclean_case": [(SAR, "c.status is Status.FINDING_CANDIDATE and c.rule_id in index", "c.status is not Status.NO_ISSUE_OBSERVED and c.rule_id in index")],
    "sarif_notifications_dropped": [(SAR, "    others = [c for c in cases if c.status not in (Status.NO_ISSUE_OBSERVED, Status.FINDING_CANDIDATE)]", "    others = []")],
    "sarif_notifications_not_capped": [(SAR, "for c in others[:MAX_NOTIFICATIONS]", "for c in others")],
    "sarif_cap_not_announced": [(SAR, "    if len(others) > MAX_NOTIFICATIONS:", "    if False:")],
    "sarif_exit_code_never_unsuccessful": [(SAR, '"executionSuccessful": result.exit_code in (0, 1),', '"executionSuccessful": True,')],
    "sarif_error_cases_are_only_warnings": [(SAR, '"level": "error" if c.status is Status.ERROR else "warning",', '"level": "warning",')],
    "sarif_uri_not_made_safe": [(SAR, "    uri = safe_uri(config_uri)", "    uri = config_uri")],
    "sarif_dotdot_uri_allowed": [(SAR, '    if _SAFE_PATH.fullmatch(path or "") and not any(part in {".", ".."} for part in path.split("/")):', '    if _SAFE_PATH.fullmatch(path or ""):')],
    "sarif_control_characters_kept": [(SAR, '    return _CONTROL.sub(" ", str(value))[:limit]', "    return str(value)[:limit]")],
    "sarif_fingerprint_ignores_the_scope": [(SAR, 'f"{result.scope_id}|{case.rule_id}|{case.key}"', 'f"{case.rule_id}|{case.key}"')],
    "sarif_privacy_notice_dropped": [(SAR, '"notice": NOTICE,', '"notice": "",')],
    "sarif_action_line_is_off_by_one": [(SAR, "item.start_mark.line + 1", "item.start_mark.line")],
    "sarif_line_may_be_zero": [(SAR, '"region": {"startLine": max(1, lines.get(case.action, 1))},', '"region": {"startLine": lines.get(case.action, 0)},')],
    "sarif_file_not_scanned_for_secrets": [(EVI, 'assert_no_secrets([json_text, md_text, sarif or "", *blobs.values()], list(secrets))', "assert_no_secrets([json_text, md_text, *blobs.values()], list(secrets))")],
    "sarif_cannot_be_read_back": [(EVI, 'if fmt not in ("json", "md", "sarif"):', 'if fmt not in ("json", "md"):')],
    "sarif_cli_ignores_the_uri_option": [(CLI, "config_uri=sarif_uri if sarif_uri is not None else config.name", "config_uri=config.name")],
    "sarif_cli_gives_no_line_numbers": [(CLI, "lines=action_lines(text))", "lines={})")],
    "openapi_size_cap_off": [(OAI, "    if len(data) > MAX_SPEC_BYTES:", "    if False:")],
    "openapi_depth_cap_off": [(OAI, "        if depth > MAX_DEPTH:", "        if False:")],
    "openapi_external_refs_followed": [(OAI, '            if not isinstance(ref, str) or not ref.startswith("#/"):', "            if False:")],
    "openapi_cyclic_schemas_loop": [(OAI, "    if not isinstance(resolved, dict) or id(resolved) in stack or depth > MAX_FIELD_DEPTH:", "    if not isinstance(resolved, dict):")],
    "openapi_writes_imported": [(OAI, 'READ_METHODS: Final = ("get", "head")', 'READ_METHODS: Final = ("get", "head", "post")')],
    "openapi_parameters_not_snake_cased": [(OAI, '    text = re.sub(r"([a-z0-9])([A-Z])", r"\\1_\\2", name).replace("-", "_").replace(".", "_").lower()', '    text = name.replace("-", "_").replace(".", "_").lower()')],
    "openapi_kind_from_the_first_parameter": [(OAI, "    last = params[-1]", "    last = params[0]")],
    "openapi_capabilities_are_open": [(OAI, "            capabilities[action_id] = []", "            capabilities[action_id] = list(ROLES)")],
    "openapi_fields_need_the_lowest_role": [(OAI, 'fields[action_id] = dict.fromkeys(paths_found, "owner")', 'fields[action_id] = dict.fromkeys(paths_found, "viewer")')],
    "openapi_paged_lists_not_detected": [(OAI, '            if isinstance(items, dict) and items.get("type") == "array":', "            if False:")],
    "openapi_header_comment_not_sanitised": [(OAI, "    return _PRINTABLE.sub(\" \", str(text)).strip()[:limit]", "    return str(text)[:limit]")],
    "openapi_property_names_not_checked": [(OAI, "        if not re.fullmatch(FIELD_PATH_PATTERN, path):", "        if False:")],
    "openapi_path_segments_not_checked": [(OAI, "        elif _SEGMENT.fullmatch(segment):", "        elif True:")],
    "openapi_operations_not_capped": [(OAI, "            if len(actions) >= MAX_OPERATIONS:", "            if False:")],
    "openapi_duplicate_ids_kept": [(OAI, "    while unique in used:", "    while False:")],
    "openapi_cli_fetches_urls_by_path": [(CLI, '    if spec.lower().startswith(("http://", "https://")):', "    if False:")],
    "openapi_cli_overwrites_silently": [(CLI, '        with output.open("w" if force else "x", encoding="utf-8") as handle:\n            handle.write(result.yaml_text)', '        with output.open("w", encoding="utf-8") as handle:\n            handle.write(result.yaml_text)')],
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
