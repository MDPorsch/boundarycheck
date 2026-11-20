"""v0.3 (docs/design-v0.3.md s3): credentials from the operating system's keychain.

Every test uses an in-memory fake backend; the real macOS, Windows and Linux stores are never touched.
Only real OS backends are ever accepted: a plaintext, file or null backend is refused."""

from __future__ import annotations

import sys
from collections.abc import Iterator
from typing import Any

import keyring
import pytest
from keyring.backend import KeyringBackend

from tests.support import dump, fake_server, fake_token, mini, parse

pytestmark = pytest.mark.milestone("V3")


class MemoryKeyring(KeyringBackend):
    """A stand-in for an OS keychain."""

    priority = 1  # type: ignore[assignment]

    def __init__(self) -> None:
        super().__init__()
        self.store: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.store.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.store[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        if (service, username) not in self.store:
            raise keyring.errors.PasswordDeleteError("not found")
        del self.store[(service, username)]


class PlaintextFileKeyring(MemoryKeyring):
    """Looks like a keyring.alt file backend: it must be refused."""


@pytest.fixture
def memory(monkeypatch: pytest.MonkeyPatch) -> Iterator[MemoryKeyring]:
    backend = MemoryKeyring()
    previous = keyring.get_keyring()
    keyring.set_keyring(backend)
    monkeypatch.setattr("boundarycheck.keychain.ACCEPTED_BACKEND_MODULES", (MemoryKeyring.__module__,))
    yield backend
    keyring.set_keyring(previous)


def _cfg(credential: dict[str, Any]) -> dict[str, Any]:
    data = mini()
    data["principals"]["alice"] = {"credential": credential}
    return data


def _bad(data: dict[str, Any], needle: str | None = None) -> None:
    from boundarycheck.config import ConfigError, parse_config  # noqa: PLC0415

    with pytest.raises(ConfigError) as caught:
        parse_config(dump(data))
    if needle is not None:
        assert needle.lower() in str(caught.value).lower(), str(caught.value)


# ------------------------------------------------------------------------------- the config ----
def test_a_keychain_credential_is_accepted_and_the_service_has_a_default() -> None:
    cred = parse(_cfg({"keychain": {"username": "alice@acme"}})).principals["alice"].credential
    assert cred is not None and cred.keychain is not None
    assert (cred.keychain.service, cred.keychain.username) == ("boundarycheck", "alice@acme")


def test_a_keychain_credential_may_choose_a_scheme_and_a_service() -> None:
    cred = parse(_cfg({"keychain": {"service": "acme-tests", "username": "bob"}, "in": "header", "name": "X-API-Key"})).principals["alice"].credential
    assert cred is not None and cred.scheme == "header" and cred.keychain is not None and cred.keychain.service == "acme-tests"


def test_a_credential_names_an_env_variable_or_a_keychain_entry_never_both() -> None:
    _bad(_cfg({"env": "BC_X", "keychain": {"username": "alice"}}), "env")


@pytest.mark.parametrize("field", ["service", "username"])
@pytest.mark.parametrize("value", ["", "a b", "a/b", "a\nb", "é", "x" * 129, "a;b", "$(x)", "a`b"])
def test_service_and_username_are_plain_tokens(field: str, value: str) -> None:
    keychain = {"service": "boundarycheck", "username": "alice", field: value}
    _bad(_cfg({"keychain": keychain}))


def test_a_keychain_entry_needs_a_username() -> None:
    _bad(_cfg({"keychain": {"service": "boundarycheck"}}), "username")


# --------------------------------------------------------------------------------- the module ----
def test_the_backend_check_accepts_a_real_os_backend_and_refuses_the_rest(memory: MemoryKeyring) -> None:
    from boundarycheck import keychain  # noqa: PLC0415

    assert keychain.backend() is memory
    keyring.set_keyring(PlaintextFileKeyring())
    with pytest.raises(keychain.KeychainError, match="operating-system"):
        keychain.backend()


def test_the_fail_and_null_backends_are_refused() -> None:
    from keyring.backends import fail, null  # noqa: PLC0415

    from boundarycheck import keychain  # noqa: PLC0415

    previous = keyring.get_keyring()
    try:
        for bad in (fail.Keyring(), null.Keyring()):
            keyring.set_keyring(bad)
            with pytest.raises(keychain.KeychainError):
                keychain.backend()
    finally:
        keyring.set_keyring(previous)


def test_the_accepted_modules_are_exactly_the_real_os_stores() -> None:
    from boundarycheck import keychain  # noqa: PLC0415

    assert set(keychain.ACCEPTED_BACKEND_MODULES) == {
        "keyring.backends.macOS", "keyring.backends.Windows", "keyring.backends.SecretService",
        "keyring.backends.kwallet", "keyring.backends.libsecret",
    }  # fmt: skip


def test_a_chain_of_backends_uses_the_first_acceptable_one_and_never_a_weaker_fallback(monkeypatch: pytest.MonkeyPatch, memory: MemoryKeyring) -> None:
    from boundarycheck import keychain  # noqa: PLC0415

    class Chain:
        backends = [PlaintextFileKeyring(), memory]

    monkeypatch.setattr(keyring, "get_keyring", lambda: Chain())
    assert keychain.backend() is memory


def test_set_get_exists_delete_round_trip_without_ever_returning_the_value_by_accident(memory: MemoryKeyring) -> None:
    from boundarycheck import keychain  # noqa: PLC0415

    secret = fake_token("kc")
    assert keychain.exists("boundarycheck", "alice") is False and keychain.get("boundarycheck", "alice") is None
    keychain.set_value("boundarycheck", "alice", secret)
    assert keychain.exists("boundarycheck", "alice") is True and keychain.get("boundarycheck", "alice") == secret
    keychain.delete("boundarycheck", "alice")
    assert keychain.exists("boundarycheck", "alice") is False
    with pytest.raises(keychain.KeychainError, match="no such"):
        keychain.delete("boundarycheck", "alice")


@pytest.mark.parametrize("value", ["short", "has space 1234", "new\nline12345", "é" * 12, "x" * 4097])
def test_only_a_usable_value_can_be_stored(memory: MemoryKeyring, value: str) -> None:
    from boundarycheck import keychain  # noqa: PLC0415

    with pytest.raises(keychain.KeychainError) as caught:
        keychain.set_value("boundarycheck", "alice", value)
    assert value not in str(caught.value) and not memory.store


def test_a_backend_failure_is_a_clear_error_that_does_not_echo_the_backend_message(monkeypatch: pytest.MonkeyPatch, memory: MemoryKeyring) -> None:
    from boundarycheck import keychain  # noqa: PLC0415

    def locked(*_a: Any) -> None:
        raise keyring.errors.KeyringLocked("password=SENTINEL-NOT-FOR-DISPLAY")

    monkeypatch.setattr(memory, "get_password", locked)
    with pytest.raises(keychain.KeychainError) as caught:
        keychain.get("boundarycheck", "alice")
    assert "SENTINEL-NOT-FOR-DISPLAY" not in str(caught.value) and "locked" in str(caught.value).lower()


def test_a_missing_extra_says_how_to_install_it(monkeypatch: pytest.MonkeyPatch) -> None:
    from boundarycheck import keychain  # noqa: PLC0415

    monkeypatch.setitem(sys.modules, "keyring", None)
    with pytest.raises(keychain.KeychainError, match=r"boundarycheck\[keychain\]"):
        keychain.get("boundarycheck", "alice")


# ------------------------------------------------------------------------------ resolution ----
def test_a_keychain_value_becomes_material_with_the_chosen_scheme(memory: MemoryKeyring) -> None:
    from boundarycheck.credentials import resolve_materials  # noqa: PLC0415

    secret = fake_token("kc")
    memory.store[("boundarycheck", "alice")] = secret
    data = _cfg({"keychain": {"username": "alice"}, "in": "cookie", "name": "session"})
    got = resolve_materials(parse(data), {})
    assert got["alice"].value == secret and (got["alice"].scheme, got["alice"].name) == ("cookie", "session")


def test_a_missing_keychain_entry_leaves_the_principal_out_with_a_note(memory: MemoryKeyring) -> None:
    from boundarycheck.credentials import resolve_materials  # noqa: PLC0415

    notes: list[str] = []
    got = resolve_materials(parse(_cfg({"keychain": {"username": "ghost"}})), {}, notes=notes)
    assert got == {} and any("alice" in n and "keychain" in n.lower() for n in notes)


def test_a_broken_keychain_is_a_note_not_a_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    from boundarycheck.credentials import resolve_materials  # noqa: PLC0415

    monkeypatch.setitem(sys.modules, "keyring", None)
    notes: list[str] = []
    assert resolve_materials(parse(_cfg({"keychain": {"username": "alice"}})), {}, notes=notes) == {}
    assert any("boundarycheck[keychain]" in n for n in notes)


def test_an_env_credential_never_asks_the_keychain(monkeypatch: pytest.MonkeyPatch) -> None:
    from boundarycheck.credentials import resolve_materials  # noqa: PLC0415

    def boom(*_a: Any) -> Any:
        raise AssertionError("the keychain must not be touched")

    monkeypatch.setattr("boundarycheck.keychain.get", boom)
    assert resolve_materials(parse(_cfg({"env": "BC_X"})), {"BC_X": fake_token()})["alice"].scheme == "bearer"


# -------------------------------------------------------------------------------------- CLI ----
def _cli(*args: str, input_: str | None = None, env: dict[str, str] | None = None) -> Any:
    from typer.testing import CliRunner  # noqa: PLC0415

    from boundarycheck.cli import app  # noqa: PLC0415

    return CliRunner().invoke(app, list(args), input=input_, env=env, catch_exceptions=False)


def test_keychain_set_prompts_twice_without_echo_and_never_prints_the_value(memory: MemoryKeyring) -> None:
    secret = fake_token("typed")
    out = _cli("keychain", "set", "--username", "alice@acme", input_=f"{secret}\n{secret}\n")
    assert out.exit_code == 0 and memory.store[("boundarycheck", "alice@acme")] == secret
    assert secret not in out.output and "stored" in out.output.lower()


def test_keychain_set_refuses_a_mismatch_and_an_unusable_value(memory: MemoryKeyring) -> None:
    assert _cli("keychain", "set", "--username", "a", input_="aaaaaaaaaa\nbbbbbbbbbb\n").exit_code == 2 and not memory.store
    out = _cli("keychain", "set", "--username", "a", input_="short\nshort\n")
    assert out.exit_code == 2 and not memory.store and "short" not in out.output.replace("shortest", "")


def test_keychain_check_reports_presence_by_exit_code_and_never_prints_the_value(memory: MemoryKeyring) -> None:
    secret = fake_token("present")
    memory.store[("boundarycheck", "alice")] = secret
    yes, no = _cli("keychain", "check", "--username", "alice"), _cli("keychain", "check", "--username", "nobody")
    assert (yes.exit_code, no.exit_code) == (0, 1) and secret not in yes.output + no.output


def test_keychain_delete_removes_the_entry(memory: MemoryKeyring) -> None:
    memory.store[("boundarycheck", "alice")] = fake_token()
    assert _cli("keychain", "delete", "--username", "alice").exit_code == 0 and not memory.store
    assert _cli("keychain", "delete", "--username", "alice").exit_code == 2


def test_keychain_commands_refuse_a_plaintext_backend() -> None:
    previous = keyring.get_keyring()
    keyring.set_keyring(PlaintextFileKeyring())
    try:
        out = _cli("keychain", "set", "--username", "alice", input_="aaaaaaaaaa\naaaaaaaaaa\n")
        assert out.exit_code == 2 and "operating-system" in out.output
    finally:
        keyring.set_keyring(previous)


def test_a_live_run_uses_a_keychain_credential_and_leaves_the_value_nowhere(memory: MemoryKeyring, tmp_path: Any) -> None:
    secret = fake_token("kcrun")
    memory.store[("boundarycheck", "alice")] = secret
    data = mini()
    data["principals"] = {"alice": {"credential": {"keychain": {"username": "alice"}, "in": "header", "name": "X-API-Key"}}}
    data["memberships"] = [{"principal": "alice", "tenant": "A", "role": "owner", "status": "active"}]
    with fake_server() as server:
        server.default = lambda h: h._send(200, {"content-type": "application/json"}, ('{"echo":"' + h.headers.get("X-API-Key", "") + '"}').encode())
        data["scope"]["target"]["base_url"] = server.base_url
        path = tmp_path / "c.yaml"
        path.write_text(dump(data))
        out = _cli("test", "--config", str(path), "--transport", "live", "--runs-dir", str(tmp_path / "r"))
        assert any(r["headers"].get("X-API-Key") == secret for r in server.requests)
    assert secret not in out.output
    for file in (tmp_path / "r").rglob("*"):
        if file.is_file():
            assert secret.encode() not in file.read_bytes(), file


def test_a_missing_keychain_entry_is_reported_and_its_cases_are_not_run(memory: MemoryKeyring, tmp_path: Any) -> None:
    data = mini()
    data["principals"] = {"alice": {"credential": {"keychain": {"username": "ghost"}}}}
    data["memberships"] = [{"principal": "alice", "tenant": "A", "role": "owner", "status": "active"}]
    with fake_server() as server:
        data["scope"]["target"]["base_url"] = server.base_url
        path = tmp_path / "c.yaml"
        path.write_text(dump(data))
        out = _cli("test", "--config", str(path), "--transport", "live", "--runs-dir", str(tmp_path / "r"))
    assert out.exit_code == 2 and "keychain" in out.output.lower() and "not_run" in out.output
