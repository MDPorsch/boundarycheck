"""OS-keychain credentials (docs/design-v0.3.md s3).

The `keyring` library is an OPTIONAL extra (`pip install "boundarycheck[keychain]"`). Only real operating-system
stores are used: macOS Keychain, Windows Credential Locker, the Linux Secret Service and KWallet. A plaintext
file, "null" or "fail" backend is refused, so this tool can never put a credential in a file. A value is read
directly from the chosen backend (never through a chain that could fall back to a weaker one) and is only ever
handed to the caller: it is not logged, not printed and not part of any error message.
"""

from __future__ import annotations

from typing import Any, Final

from boundarycheck.credentials import SECRET_VALUE

ACCEPTED_BACKEND_MODULES: Final = (
    "keyring.backends.macOS",
    "keyring.backends.Windows",
    "keyring.backends.SecretService",
    "keyring.backends.kwallet",
    "keyring.backends.libsecret",
)
NOT_INSTALLED: Final = (
    'the OS keychain needs the optional extra: pip install "boundarycheck[keychain]" '
    '(or: uv tool install "boundarycheck[keychain]")'
)
NO_OS_STORE: Final = (
    "no operating-system keychain is available (boundarycheck only uses the macOS Keychain, the Windows "
    "Credential Locker, the Linux Secret Service or KWallet, never a file or a plaintext backend)"
)


class KeychainError(Exception):
    """A keychain problem. The message is safe to show: it never contains a value."""


def _lib() -> Any:
    try:
        import keyring  # noqa: PLC0415
    except ImportError:
        raise KeychainError(NOT_INSTALLED) from None
    if keyring is None:  # a module blocked in sys.modules
        raise KeychainError(NOT_INSTALLED)
    return keyring


def _accepted(candidate: Any) -> bool:
    module = type(candidate).__module__
    return any(module == name or module.startswith(name + ".") for name in ACCEPTED_BACKEND_MODULES)


def backend() -> Any:
    """The operating-system backend to use. A chain is searched for its first acceptable member."""
    chosen = _lib().get_keyring()
    for candidate in getattr(chosen, "backends", None) or [chosen]:
        if _accepted(candidate):
            return candidate
    raise KeychainError(NO_OS_STORE)


def _call(action: str, function: Any, *args: str) -> Any:
    lib = _lib()
    try:
        return function(*args)
    except lib.errors.KeyringLocked:
        raise KeychainError(f"the keychain is locked; unlock it and try again ({action})") from None
    except lib.errors.PasswordDeleteError:
        raise KeychainError("no such keychain entry") from None
    except lib.errors.KeyringError:
        raise KeychainError(f"the keychain could not complete the request ({action})") from None


def get(service: str, username: str) -> str | None:
    value = _call("read", backend().get_password, service, username)
    return value if isinstance(value, str) else None


def exists(service: str, username: str) -> bool:
    return get(service, username) is not None


def set_value(service: str, username: str, value: str) -> None:
    if SECRET_VALUE.fullmatch(value) is None:
        raise KeychainError("the value must be 8 to 4096 printable ASCII characters without spaces")
    _call("write", backend().set_password, service, username, value)


def delete(service: str, username: str) -> None:
    _call("delete", backend().delete_password, service, username)
