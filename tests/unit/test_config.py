"""The config loader is the only place user-controlled structure is parsed: it gets the most negative
tests. Specified in docs/contract.md s6; written before the code (milestone S1)."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from tests.support import EXAMPLE, dump, mini, parse

pytestmark = pytest.mark.milestone("S1")


def _err() -> type[Exception]:
    from boundarycheck.config import ConfigError  # noqa: PLC0415

    return ConfigError


def _bad(text: str, fragment: str | None = None) -> None:
    from boundarycheck.config import parse_config  # noqa: PLC0415

    with pytest.raises(_err()) as info:
        parse_config(text)
    if fragment is not None:
        assert fragment.lower() in str(info.value).lower(), str(info.value)


def test_the_example_and_the_mini_config_are_valid() -> None:
    from boundarycheck.config import load_config  # noqa: PLC0415

    cfg = load_config(EXAMPLE)
    assert cfg.scope.id == "lab-demo" and len(cfg.principals) == 7
    assert parse(mini()).scope.id == "unit"


# ------------------------------------------------------------------- the YAML layer ----
def test_aliases_are_refused_so_an_alias_bomb_cannot_expand() -> None:
    bomb = "a: &a [x,x,x,x,x,x,x,x,x]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\nc: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\nd: *c\n"
    _bad(bomb, "alias")


def test_a_bare_anchor_is_refused_too() -> None:
    _bad("version: &v 1\nscope: {}\n", "anchor")


def test_duplicate_keys_are_refused_at_the_top_level_and_nested() -> None:
    _bad("version: 1\nversion: 1\n", "duplicate")
    text = dump(mini()).replace("policy:", "policy:\n  roles: [viewer]", 1)
    _bad(text, "duplicate")


def test_python_object_tags_are_refused_and_never_executed(tmp_path: Path) -> None:
    marker = tmp_path / "pwned"
    _bad(f"version: !!python/object/apply:os.system ['touch {marker}']\n")
    assert not marker.exists()


def test_the_size_cap_is_enforced_before_parsing(tmp_path: Path) -> None:
    from boundarycheck.config import MAX_CONFIG_BYTES, load_config  # noqa: PLC0415

    big = tmp_path / "big.yaml"
    big.write_text("version: 1\n# " + "x" * (MAX_CONFIG_BYTES + 10) + "\n")
    with pytest.raises(_err(), match=r"(?i)too large"):
        load_config(big)


def test_deep_nesting_is_refused() -> None:
    _bad("version: 1\nx: " + "[" * 200 + "]" * 200 + "\n", "deep")


def test_non_mapping_documents_and_multiple_documents_are_refused() -> None:
    _bad("- a\n- b\n", "mapping")
    _bad("version: 1\n---\nversion: 1\n", "document")
    _bad("", "empty")


def test_a_missing_or_unreadable_file_is_a_config_error_not_a_traceback(tmp_path: Path) -> None:
    from boundarycheck.config import load_config  # noqa: PLC0415

    with pytest.raises(_err()):
        load_config(tmp_path / "nope.yaml")
    with pytest.raises(_err()):
        load_config(tmp_path)  # a directory


def test_binary_garbage_is_a_config_error() -> None:
    from boundarycheck.config import parse_config  # noqa: PLC0415

    with pytest.raises(_err()):
        parse_config(b"\xff\xfe\x00garbage")


# --------------------------------------------------------------------- the schema ----
def test_unknown_keys_are_refused_everywhere() -> None:
    for path in ([], ["scope"], ["scope", "target"], ["policy"], ["actions", 0], ["resources", 0]):
        data = mini()
        node: Any = data
        for part in path:
            node = node[part]
        node["surprise"] = 1
        _bad(dump(data), "surprise")


def test_credentials_can_never_be_written_into_the_config() -> None:
    data = mini()
    data["principals"]["alice"]["credential"] = {"token": ".".join(("eyJhbGciOi", "fake", "token"))}
    _bad(dump(data), "token")
    data = mini()
    data["principals"]["alice"]["token"] = "x"
    _bad(dump(data), "token")


def test_a_credential_names_an_environment_variable_in_a_strict_format() -> None:
    for name in ("lower", "1BAD", "HAS SPACE", "A-B", "", "X" * 65):
        data = mini()
        data["principals"]["alice"]["credential"] = {"env": name}
        _bad(dump(data))


def test_a_credential_needs_something_to_name() -> None:
    data = mini()
    data["principals"]["alice"]["credential"] = {}
    _bad(dump(data), "credential")


def test_no_type_coercion_an_unquoted_number_is_not_a_string() -> None:
    data = mini()
    data["resources"][4]["ids"]["project_id"] = 1234
    _bad(dump(data))
    data = mini()
    data["scope"]["id"] = True
    _bad(dump(data))


@pytest.mark.parametrize(
    "bad",
    [
        "../etc",
        "a/b",
        "a b",
        "a?b",
        "a#b",
        "%2e%2e",
        "a\nb",
        "é",
        "",
        ".hidden",
        "x" * 129,
        "a\\b",
        "a@b",
    ],
)
def test_identifiers_are_validated_against_a_strict_alphabet(bad: str) -> None:
    data = mini()
    data["resources"][4]["ids"]["project_id"] = bad
    _bad(dump(data))


# The v0.1 pins "only GET and HEAD are accepted" and "POST is refused" were superseded by
# docs/contract.md s9 (write actions are accepted and run on the fixture transport only). Their
# replacements, and the tests that no live transport ever sends a write, are in tests/unit/test_writes.py
# and tests/negative/test_live_transport.py.


@pytest.mark.parametrize(
    "path",
    [
        "v1/x",
        "/v1/{a}/../x",
        "//evil/x",
        "/v1/x?y=1",
        "/v1/x#f",
        "/v1/ x",
        "/v1/{a b}",
        "/v1/%2e%2e/x",
        "/v1\\x",
        "http://evil/x",
        "/" + "a" * 300,
    ],
)
def test_action_paths_cannot_smuggle_an_authority_traversal_or_a_query(path: str) -> None:
    data = mini()
    data["actions"][0]["path"] = path
    _bad(dump(data))


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1:8000",  # not http
        "http://example.com",
        "http://127.0.0.1.evil.example",
        "http://user:pw@127.0.0.1:8000",
        "http://0.0.0.0:8000",
        "http://10.0.0.5",
        "http://[2001:db8::1]:8000",
        "http://2130706433",  # decimal form of 127.0.0.1: a name, not a literal
        "http://127.1",
        "http://localhost.:8000",
        "http://127.0.0.1:8000/base?x=1",
        "http://127.0.0.1:8000#frag",
        "ftp://127.0.0.1",
        "file:///etc/passwd",
        "http://127.0.0.1:99999",
    ],
)
def test_a_remote_or_odd_base_url_is_refused(url: str) -> None:
    data = mini()
    data["scope"]["target"]["base_url"] = url
    _bad(dump(data))


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8000",
        "http://127.0.0.1",
        "http://127.5.5.5:1",
        "http://[::1]:8000",
        "http://localhost:8000",
        "http://LOCALHOST:8000/",
    ],
)
def test_loopback_base_urls_are_accepted(url: str) -> None:
    data = mini()
    data["scope"]["target"]["base_url"] = url
    assert parse(data).scope.target.base_url is not None


def test_the_refusal_of_a_remote_host_names_what_v0_2_will_require() -> None:
    data = mini()
    data["scope"]["target"]["base_url"] = "https://api.example.com"
    _bad(dump(data), "loopback")
    from boundarycheck.config import parse_config  # noqa: PLC0415

    with pytest.raises(_err()) as info:
        parse_config(dump(data))
    assert "v0.2" in str(info.value)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("request_budget", 0),
        ("request_budget", 10**7),
        ("rate_limit_rps", 0),
        ("rate_limit_rps", -1),
        ("timeout_seconds", 0),
        ("max_response_bytes", 10),
    ],
)
def test_limits_have_sane_bounds(field: str, value: float) -> None:
    data = mini()
    data["scope"]["target"][field] = value
    _bad(dump(data))


# ------------------------------------------------------------------ cross-references ----
def _break(mutator: Any, fragment: str) -> None:
    data = mini()
    mutator(data)
    _bad(dump(data), fragment)


def test_every_reference_must_resolve() -> None:
    _break(
        lambda d: d["memberships"].append({"principal": "ghost", "tenant": "A", "role": "viewer", "status": "active"}),
        "ghost",
    )
    _break(
        lambda d: d["memberships"].append({"principal": "alice", "tenant": "Z", "role": "viewer", "status": "active"}),
        "Z",
    )
    _break(
        lambda d: d["memberships"].append({"principal": "alice", "tenant": "B", "role": "wizard", "status": "active"}),
        "wizard",
    )
    _break(lambda d: d["resources"][4].__setitem__("tenant", "Z"), "Z")
    _break(lambda d: d["actions"][0].__setitem__("resource_kind", "invoice"), "invoice")


def test_keys_must_be_unique() -> None:
    _break(lambda d: d["tenants"].append(copy.deepcopy(d["tenants"][0])), "duplicate")
    _break(lambda d: d["resources"].append(copy.deepcopy(d["resources"][4])), "duplicate")
    _break(lambda d: d["actions"].append(copy.deepcopy(d["actions"][0])), "duplicate")
    _break(lambda d: d["memberships"].append(copy.deepcopy(d["memberships"][0])), "duplicate")


def test_anonymous_is_reserved() -> None:
    _break(lambda d: d["principals"].__setitem__("anonymous", {}), "anonymous")


def test_a_missing_resource_has_no_tenant_and_an_existing_one_must_have_one() -> None:
    _break(lambda d: d["resources"][3].__setitem__("tenant", "A"), "exists")
    _break(lambda d: d["resources"][4].pop("tenant"), "tenant")


def test_every_path_parameter_must_be_supplied_by_every_resource_of_the_kind() -> None:
    _break(lambda d: d["resources"][4]["ids"].clear(), "project_id")
    _break(lambda d: d["actions"][0].__setitem__("path", "/v1/projects/{nope}"), "nope")


def test_policy_must_be_complete_default_deny_is_not_a_hole() -> None:
    _break(lambda d: d["policy"]["capabilities"].pop("project.read"), "project.read")
    _break(
        lambda d: d["policy"]["capabilities"].__setitem__("project.read", ["viewer", "wizard"]),
        "wizard",
    )
    _break(lambda d: d["policy"]["fields"].pop("project.detail"), "project.detail")
    _break(lambda d: d["policy"]["fields"]["project.detail"].__setitem__("id", "wizard"), "wizard")
    _break(lambda d: d["policy"].__setitem__("roles", ["viewer", "viewer"]), "roles")


def test_a_list_spec_must_point_at_real_things() -> None:
    _break(lambda d: d["actions"][1]["list"].__setitem__("kind", "invoice"), "invoice")
    _break(lambda d: d["actions"][1]["list"].__setitem__("id_key", "nope"), "nope")


def test_an_error_never_echoes_the_offending_value() -> None:
    data = mini()
    data["principals"]["alice"]["credential"] = {"env": "lowercase-secret-value-12345"}
    from boundarycheck.config import parse_config  # noqa: PLC0415

    with pytest.raises(_err()) as info:
        parse_config(dump(data))
    assert "lowercase-secret-value-12345" not in str(info.value)


# ----------------------------------------- properties that only one layer protects ----
def test_a_numeric_limit_must_be_a_number_not_a_string_that_looks_like_one() -> None:
    data = mini()
    data["scope"]["target"]["request_budget"] = "5"
    _bad(dump(data))
    data = mini()
    data["scope"]["target"]["rate_limit_rps"] = "5"
    _bad(dump(data))


@pytest.mark.parametrize(
    "path",
    [
        "/v1/projects/{project_id}\n",
        "/v1/projects/{project_id}/../x",
        "/v1/projects/{project_id}/./x",
        "/v1/projects/{project_id}/..",
    ],
)
def test_a_path_is_checked_whole_a_trailing_newline_or_a_dot_segment_is_not_hidden(path: str) -> None:
    data = mini()
    data["actions"][0]["path"] = path  # every parameter used here IS supplied: only the path rule can refuse it
    _bad(dump(data))


@pytest.mark.parametrize("name", ["BC_X\n", "BC_X ", " BC_X"])
def test_an_environment_variable_name_is_checked_whole(name: str) -> None:
    data = mini()
    data["principals"]["alice"]["credential"] = {"env": name}
    _bad(dump(data))


def test_an_identifier_with_a_trailing_newline_is_refused() -> None:
    data = mini()
    data["resources"][4]["ids"]["project_id"] = "pa1\n"
    _bad(dump(data))


def test_an_ipv4_mapped_ipv6_address_is_never_treated_as_loopback() -> None:
    for url in ("http://[::ffff:127.0.0.1]:8000", "http://[::ffff:7f00:1]:8000"):
        data = mini()
        data["scope"]["target"]["base_url"] = url
        _bad(dump(data), "loopback")


def test_a_credential_is_a_mapping_with_known_keys_only() -> None:
    data = mini()
    data["principals"]["alice"]["credential"] = "tok-not-a-mapping"
    _bad(dump(data))


def test_merge_keys_are_refused_because_they_can_hide_a_duplicate_key() -> None:
    """`<<` merges another mapping in and lets an explicit key silently override it: it would bypass the
    duplicate-key check (and needs no alias, so the alias/anchor refusal does not cover it)."""
    text = dump(mini()).replace("scope:\n", "scope:\n  <<: {id: other}\n", 1)
    assert "<<:" in text
    _bad(text, "merge")
