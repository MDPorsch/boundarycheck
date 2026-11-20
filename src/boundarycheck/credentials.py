"""Credential material (docs/design-v0.3.md s2).

A principal's credential is a bearer token, an API key in a named header, or a named session cookie. The
VALUE is read from the environment (or the OS keychain, s3) and held only here and in the transport; it is
never in the config and never in a report. `repr()` of a `Material` never shows the value.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final, Literal

if TYPE_CHECKING:
    from boundarycheck.config import Config

Scheme = Literal["bearer", "header", "cookie"]

#: Printable ASCII without spaces: safe as a header value, and long enough to be a credential.
SECRET_VALUE: Final = re.compile(r"[\x21-\x7e]{8,4096}")
#: RFC 6265 cookie-octet: no space, double quote, comma, semicolon or backslash, so a value can never
#: smuggle a second cookie into the request.
COOKIE_VALUE: Final = re.compile(r"[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]{8,4096}")
HEADER_NAME: Final = re.compile(r"[A-Za-z0-9-]{1,64}")
COOKIE_NAME: Final = re.compile(r"[A-Za-z0-9_.-]{1,64}")
PREFIX: Final = re.compile(r"[\x20-\x7e]{1,32}")
#: Headers that change how the request is framed or routed, or that the tool sets itself.
FORBIDDEN_HEADERS: Final = frozenset(
    {
        "host", "content-length", "content-type", "transfer-encoding", "connection", "upgrade", "te",
        "trailer", "accept", "accept-encoding", "user-agent", "proxy-authorization", "cookie", "set-cookie",
    }
)  # fmt: skip


@dataclass(frozen=True)
class Material:
    """One principal's resolved credential. The value never appears in `repr`."""

    value: str = field(repr=False)
    scheme: Scheme = "bearer"
    name: str | None = None
    prefix: str = ""

    def usable(self) -> bool:
        pattern = COOKIE_VALUE if self.scheme == "cookie" else SECRET_VALUE
        return pattern.fullmatch(self.value) is not None

    def header(self) -> tuple[str, str]:
        """The (name, value) the transport sends for this credential."""
        if self.scheme == "header":
            return str(self.name), f"{self.prefix}{self.value}"
        if self.scheme == "cookie":
            return "Cookie", f"{self.name}={self.value}"
        return "Authorization", f"Bearer {self.value}"


def resolve_materials(
    config: Config, environ: Mapping[str, str], *, notes: list[str] | None = None
) -> dict[str, Material]:
    """Materials for every principal whose credential names a source that holds a usable value. A principal
    with no value, or an unusable one, is left out, so its cases are `not_run` and never sent. `notes`
    collects a human reason for each keychain problem (never a value)."""
    from boundarycheck import keychain  # noqa: PLC0415

    found: dict[str, Material] = {}
    for key, principal in config.principals.items():
        cred = principal.credential
        if cred is None:
            continue
        value: str | None = None
        if cred.env is not None:
            value = environ.get(cred.env)
        elif cred.keychain is not None:
            try:
                value = keychain.get(cred.keychain.service, cred.keychain.username)
            except keychain.KeychainError as exc:
                if notes is not None:
                    notes.append(f"principal '{key}': {exc}")
                continue
            if value is None and notes is not None:
                notes.append(
                    f"principal '{key}': no keychain entry for service '{cred.keychain.service}' and that username"
                )
        if value is None:
            continue
        material = Material(value=value, scheme=cred.scheme, name=cred.name, prefix=cred.prefix or "")
        if material.usable():
            found[key] = material
    return found
