"""Redaction and the secret-leak guard (docs/contract.md s7)."""

from __future__ import annotations

import json

import pytest

from tests.support import fake_jwt, fake_token

pytestmark = pytest.mark.milestone("S1")

JWT = fake_jwt()


def _r(**kw):  # type: ignore[no-untyped-def]
    from boundarycheck.redact import Redactor  # noqa: PLC0415

    return Redactor(mask_fields=kw.get("mask", []), secrets=kw.get("secrets", []))


def test_jwt_shaped_strings_email_addresses_and_long_runs_are_replaced() -> None:
    out = _r().text(f"t={JWT} mail=alice@tenantlab.invalid hex={'a1' * 24} b64={'QUJD' * 12}")
    assert JWT not in out and "alice@" not in out and "a1a1a1" not in out and "QUJDQUJD" not in out
    assert "[redacted-jwt]" in out and "[redacted-email]" in out and "[redacted-long-string]" in out


def test_ordinary_ids_and_short_words_survive() -> None:
    text = "project 50000000-0000-4000-8000-000000000001 status active 12345"
    assert _r().text(text) == text


def test_sensitive_headers_lose_their_values_whatever_the_case() -> None:
    out = _r().headers(
        {
            "Authorization": "Bearer abc",
            "COOKIE": "s=1",
            "Set-Cookie": "s=2",
            "Proxy-Authorization": "x",
            "Content-Type": "application/json",
            "X-Other": "ok",
        }
    )
    assert out["Authorization"] == "[redacted]" and out["COOKIE"] == "[redacted]"
    assert out["Set-Cookie"] == "[redacted]" and out["Proxy-Authorization"] == "[redacted]"
    assert out["Content-Type"] == "application/json" and out["X-Other"] == "ok"


def test_masked_fields_are_replaced_at_any_depth_including_inside_lists() -> None:
    body = json.dumps(
        {
            "a": {"email_private": "x"},
            "items": [{"email_private": "y", "keep": 1}],
            "email_private": "z",
        }
    ).encode()
    out = json.loads(_r(mask=["email_private"]).body(body, "application/json"))
    assert out["a"]["email_private"] == "[masked]" and out["items"][0]["email_private"] == "[masked]"
    assert out["email_private"] == "[masked]" and out["items"][0]["keep"] == 1


def test_an_exact_credential_value_is_removed_wherever_it_appears() -> None:
    secret = fake_token()
    out = _r(secrets=[secret]).text(f"echo {secret} and again {secret}")
    assert secret not in out and "[credential]" in out
    body = json.dumps({"k": secret}).encode()
    assert secret not in _r(secrets=[secret]).body(body, "application/json")


def test_a_json_body_that_is_not_valid_json_is_still_redacted_as_text() -> None:
    out = _r().body(f"not json {JWT}".encode(), "application/json")
    assert JWT not in out


def test_an_undecodable_body_is_still_handled() -> None:
    out = _r().body(b"\xff\xfe\xfdabc", "application/octet-stream")
    assert isinstance(out, str)


def test_the_observation_blob_is_bounded_and_marks_truncation() -> None:
    from boundarycheck.model import Observation  # noqa: PLC0415

    big = Observation(status=200, headers={"content-type": "text/plain"}, body=b"x " * 200_000)
    blob = _r().observation(big)
    assert blob["truncated"] is True and len(blob["body"]) <= 65_536
    small = _r().observation(Observation(status=404, headers={}, body=b"{}"))
    assert small["truncated"] is False and small["status"] == 404


def test_the_leak_guard_finds_a_secret_and_never_repeats_it() -> None:
    from boundarycheck.redact import SecretLeakError, assert_no_secrets  # noqa: PLC0415

    secret = fake_token()
    with pytest.raises(SecretLeakError) as info:
        assert_no_secrets(["clean", f"a {secret} b"], [secret])
    assert secret not in str(info.value)
    assert_no_secrets(["clean text"], [secret])


def test_the_leak_guard_ignores_empty_and_tiny_secrets_that_would_match_everything() -> None:
    from boundarycheck.redact import assert_no_secrets  # noqa: PLC0415

    assert_no_secrets(["abc abc abc"], ["", "a", "abc"])


def test_redaction_is_idempotent() -> None:
    once = _r().text(f"{JWT} bob@x.invalid")
    assert _r().text(once) == once
