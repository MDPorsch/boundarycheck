"""Remote live mode, the pure rules (docs/remote-live-design.md s4.1-4.3, s4.6): which addresses may be
connected to, and which configs may name a remote host. No socket is opened here."""

from __future__ import annotations

from typing import Any

import pytest

from tests.support import dump, mini, parse

pytestmark = pytest.mark.milestone("R1")


def _check(address: str, networks: tuple[str, ...] = ()) -> str | None:
    """None if the address is acceptable, else the refusal reason."""
    from boundarycheck.netcheck import AddressRefused, check_address  # noqa: PLC0415

    try:
        check_address(address, networks)
    except AddressRefused as exc:
        return str(exc)
    return None


PUBLIC = ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111", "2a00:1450:4009:81f::200e"]
# never, whatever the operator lists
NEVER = [
    "0.0.0.0", "0.1.2.3", "169.254.169.254", "169.254.0.1", "224.0.0.1", "239.255.255.250", "255.255.255.255",
    "240.0.0.1", "::", "fe80::1", "febf::1", "ff02::1",
    "::ffff:8.8.8.8", "::ffff:10.0.0.1", "::ffff:169.254.169.254", "64:ff9b::808:808", "64:ff9b::a00:1",
    "2002:808:808::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2", "::8.8.8.8",
]  # fmt: skip
# refused unless the operator writes the range down
PRIVATE = [
    "127.0.0.1", "127.255.255.254", "::1", "10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.254",
    "192.168.0.1", "100.64.0.1", "100.127.255.254", "fc00::1", "fd12:3456::1",
]  # fmt: skip


@pytest.mark.parametrize("address", PUBLIC)
def test_a_public_address_is_acceptable_without_any_allowlist(address: str) -> None:
    assert _check(address) is None


@pytest.mark.parametrize("address", NEVER)
def test_these_addresses_are_refused_even_if_the_operator_lists_a_range_around_them(address: str) -> None:
    assert _check(address) is not None
    assert _check(address, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")) is not None


@pytest.mark.parametrize("address", PRIVATE)
def test_a_private_loopback_or_shared_address_is_refused_unless_its_range_is_listed(address: str) -> None:
    assert _check(address) is not None
    listed = {
        "127.": "127.0.0.0/8", "::1": "::1/128", "10.": "10.0.0.0/8", "172.": "172.16.0.0/12",
        "192.": "192.168.0.0/16", "100.": "100.64.0.0/10", "fc": "fc00::/7", "fd": "fc00::/7",
    }  # fmt: skip
    network = next(v for k, v in listed.items() if address.startswith(k))
    assert _check(address, (network,)) is None


def test_a_listed_range_does_not_admit_an_address_outside_it() -> None:
    assert _check("10.1.2.3", ("10.1.0.0/16",)) is None
    assert _check("10.2.2.3", ("10.1.0.0/16",)) is not None
    assert _check("192.168.1.1", ("10.0.0.0/8",)) is not None


def test_a_public_address_needs_no_listing_but_a_listing_does_not_forbid_it() -> None:
    assert _check("8.8.8.8", ("10.0.0.0/8",)) is None


@pytest.mark.parametrize("address", ["fe80::1%eth0", "fe80::1%1", "8.8.8.8%lo", "::1%lo"])
def test_a_zone_id_is_refused(address: str) -> None:
    assert _check(address, ("::1/128",)) is not None


@pytest.mark.parametrize("address", ["", "localhost", "not-an-ip", "1.2.3", "1.2.3.4.5", "999.1.1.1", "0x7f.1", "2130706433", " 8.8.8.8", "8.8.8.8 "])
def test_anything_that_is_not_a_plain_ip_literal_is_refused(address: str) -> None:
    assert _check(address, ("127.0.0.0/8",)) is not None


def test_the_refusal_says_why_and_never_echoes_a_long_input() -> None:
    reason = _check("169.254.169.254") or ""
    assert "169.254.169.254" in reason and ("metadata" in reason or "link-local" in reason)
    long = _check("x" * 500) or ""
    assert len(long) < 200


# --------------------------------------------------------------------------- the config ----
def remote(**changes: Any) -> dict[str, Any]:
    """`mini()` pointed at one remote host, fully declared."""
    data = mini()
    data["scope"]["target"].update(
        {
            "base_url": "https://api.staging.acme.example",
            "allowed_hosts": ["api.staging.acme.example"],
        }
    )
    data["scope"]["authorization"] = {"engagement": "ACME-2026-114", "not_after": "2030-01-01T00:00:00Z"}
    for dotted, value in changes.items():
        node = data
        *parents, leaf = dotted.split("__")
        for key in parents:
            node = node[key]
        if value is DELETE:
            del node[leaf]
        else:
            node[leaf] = value
    return data


DELETE = object()


def _bad(data: dict[str, Any], needle: str | None = None) -> None:
    from boundarycheck.config import ConfigError, parse_config  # noqa: PLC0415

    with pytest.raises(ConfigError) as caught:
        parse_config(dump(data))
    if needle is not None:
        assert needle.lower() in str(caught.value).lower(), str(caught.value)


def test_a_fully_declared_remote_target_is_accepted() -> None:
    cfg = parse(remote())
    target = cfg.scope.target
    assert target.base_url == "https://api.staging.acme.example" and target.allowed_hosts == ["api.staging.acme.example"]
    assert cfg.scope.authorization is not None and cfg.scope.authorization.engagement == "ACME-2026-114"
    assert target.is_remote and target.effective_rate_limit_rps == 2.0  # the default for a remote host


def test_a_loopback_target_is_not_remote_and_keeps_its_rate() -> None:
    target = parse(mini()).scope.target
    assert not target.is_remote and target.effective_rate_limit_rps == target.rate_limit_rps


def test_an_explicit_rate_is_honoured_up_to_the_cap() -> None:
    assert parse(remote(scope__target__rate_limit_rps=20)).scope.target.effective_rate_limit_rps == 20
    assert parse(remote(scope__target__rate_limit_rps=0.5)).scope.target.effective_rate_limit_rps == 0.5
    _bad(remote(scope__target__rate_limit_rps=20.5), "rate")
    _bad(remote(scope__target__rate_limit_rps=1000), "rate")


@pytest.mark.parametrize(
    ("url", "needle"),
    [
        ("http://api.staging.acme.example", "https"),
        ("https://user:pw@api.staging.acme.example", "credentials"),
        ("https://api.staging.acme.example/v1", "only scheme"),
        ("https://api.staging.acme.example/?x=1", "only scheme"),
        ("https://api.staging.acme.example/#f", "only scheme"),
        ("ftp://api.staging.acme.example", "https"),
        ("https://", "host"),
        ("https://api.staging.acme.example:99999", "url"),
        ("https://[::1", "url"),
    ],
)
def test_a_remote_url_must_be_plain_https_scheme_host_and_optional_port(url: str, needle: str) -> None:
    _bad(remote(scope__target__base_url=url), needle)


def test_the_declared_host_must_match_the_url_exactly() -> None:
    _bad(remote(scope__target__allowed_hosts=["other.acme.example"]), "allowed_hosts")
    _bad(remote(scope__target__allowed_hosts=[]), "allowed_hosts")
    _bad(remote(scope__target__allowed_hosts=DELETE), "allowed_hosts")


def test_there_is_exactly_one_allowed_host() -> None:
    _bad(remote(scope__target__allowed_hosts=["api.staging.acme.example", "api.prod.acme.example"]), "exactly one")


@pytest.mark.parametrize("host", ["*.acme.example", "*", "acme.*", "API.staging.acme.example", "api.staging.acme.example.", "api staging.acme.example", "münchen.example", "xn--a.example/x"])
def test_the_allowed_host_is_an_exact_lowercase_ascii_name(host: str) -> None:
    _bad(remote(scope__target__allowed_hosts=[host]))


def test_a_port_other_than_443_must_be_written_in_the_allowlist() -> None:
    ok = parse(remote(scope__target__base_url="https://api.staging.acme.example:8443", scope__target__allowed_hosts=["api.staging.acme.example:8443"]))
    assert ok.scope.target.allowed_hosts == ["api.staging.acme.example:8443"]
    _bad(remote(scope__target__base_url="https://api.staging.acme.example:8443"), "allowed_hosts")
    _bad(remote(scope__target__base_url="https://api.staging.acme.example:443", scope__target__allowed_hosts=["api.staging.acme.example:8443"]), "allowed_hosts")


def test_the_default_port_may_be_written_either_way() -> None:
    parse(remote(scope__target__base_url="https://api.staging.acme.example:443"))
    parse(remote(scope__target__allowed_hosts=["api.staging.acme.example:443"]))


def test_an_ip_literal_host_is_accepted_only_when_its_range_is_listed() -> None:
    _bad(remote(scope__target__base_url="https://10.20.0.5", scope__target__allowed_hosts=["10.20.0.5"]), "allowed_networks")
    ok = parse(remote(scope__target__base_url="https://10.20.0.5", scope__target__allowed_hosts=["10.20.0.5"], scope__target__allowed_networks=["10.20.0.0/16"]))
    assert ok.scope.target.is_remote
    _bad(remote(scope__target__base_url="https://169.254.169.254", scope__target__allowed_hosts=["169.254.169.254"]), "never")
    _bad(remote(scope__target__base_url="https://[::ffff:8.8.8.8]", scope__target__allowed_hosts=["[::ffff:8.8.8.8]"]), "never")


def test_a_public_ip_literal_is_accepted() -> None:
    parse(remote(scope__target__base_url="https://93.184.216.34", scope__target__allowed_hosts=["93.184.216.34"]))


@pytest.mark.parametrize("network", ["169.254.0.0/16", "169.254.169.254/32", "0.0.0.0/0", "128.0.0.0/1", "::/0", "fe80::/10", "224.0.0.0/4", "240.0.0.0/4", "::ffff:0:0/96", "64:ff9b::/96", "2002::/16", "not-a-network", "10.0.0.0/33", "10.0.0.1"])
def test_a_listed_range_that_includes_an_always_refused_address_is_refused_at_load(network: str) -> None:
    _bad(remote(scope__target__allowed_networks=[network]), "allowed_networks")


@pytest.mark.parametrize("network", ["10.20.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7", "127.0.0.0/8", "10.20.0.7/32"])
def test_a_listed_private_range_is_accepted(network: str) -> None:
    assert parse(remote(scope__target__allowed_networks=[network])).scope.target.allowed_networks == [network]


def test_allowed_networks_are_capped() -> None:
    _bad(remote(scope__target__allowed_networks=[f"10.{n}.0.0/16" for n in range(40)]), "allowed_networks")


# ----------------------------------------------------------------------- authorization ----
def test_a_remote_target_needs_an_authorization_block() -> None:
    _bad(remote(scope__authorization=DELETE), "authorization")


@pytest.mark.parametrize("engagement", ["", " ", "x" * 121, "line\nbreak", "tab\there", "\x00", "esc\x1b[0m", "bidi‮"])
def test_the_engagement_reference_is_short_plain_text(engagement: str) -> None:
    _bad(remote(scope__authorization__engagement=engagement))


def test_not_after_is_required() -> None:
    _bad(remote(scope__authorization__not_after=DELETE), "not_after")


@pytest.mark.parametrize("value", ["2030-01-01T00:00:00", "2030-01-01", "tomorrow", 5, None])
def test_the_window_needs_timestamps_with_a_time_zone(value: Any) -> None:
    _bad(remote(scope__authorization__not_after=value))


def test_the_window_must_be_ordered_and_not_absurdly_long() -> None:
    parse(remote(scope__authorization__not_before="2029-01-01T00:00:00Z"))
    _bad(remote(scope__authorization__not_before="2031-01-01T00:00:00Z"), "not_before")
    _bad(remote(scope__authorization__not_before="2020-01-01T00:00:00Z"), "window")  # longer than a year


def test_an_unknown_authorization_key_is_refused() -> None:
    _bad(remote(scope__authorization__approved_by="me"))


def test_a_loopback_config_needs_no_authorization_and_ignores_none() -> None:
    assert parse(mini()).scope.authorization is None


def test_ca_bundle_is_an_optional_path_string() -> None:
    assert parse(remote(scope__target__ca_bundle="./acme-ca.pem")).scope.target.ca_bundle == "./acme-ca.pem"
    _bad(remote(scope__target__ca_bundle=["a"]))
    _bad(remote(scope__target__ca_bundle="x" * 600), "ca_bundle")


def test_a_remote_url_in_a_loopback_style_config_is_still_refused_without_the_declaration() -> None:
    data = mini()
    data["scope"]["target"]["base_url"] = "https://api.staging.acme.example"
    _bad(data, "allowed_hosts")
