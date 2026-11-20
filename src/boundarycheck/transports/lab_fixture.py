"""The built-in `tenant-boundary-lab` adapter: the lab served in process (no socket).

This is the ONLY module that knows the lab exists, and it imports it lazily so that installing
boundarycheck never requires, and never installs, the lab. A source checkout provides it as the
`lab/` submodule (docs/contract.md s5). Credentials are minted per run with an ephemeral Ed25519 key
that never leaves memory.
"""

from __future__ import annotations

import sqlite3
import tempfile
import time
import uuid
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Final, NamedTuple

import httpx

from boundarycheck.config import Config
from boundarycheck.model import Observation, PolicyRefusal, TransportUnavailable
from boundarycheck.statediff import Snapshot, SnapshotError
from boundarycheck.transports.sqlite_state import snapshot_sqlite

ISSUER: Final = "https://issuer.boundarycheck.invalid"
AUDIENCE: Final = "boundarycheck-lab"
LAB_ENV: Final = {"LAB_MODE": "1", "TENANTLAB_ENV": "test"}
READ_METHODS: Final = ("GET", "HEAD")
WRITE_METHODS: Final = ("POST", "PUT", "PATCH", "DELETE")
NOT_INSTALLED: Final = (
    "the 'tenant-boundary-lab' fixture needs the lab installed from a source checkout "
    "(git clone --recurse-submodules, then 'uv sync'); a wheel install of boundarycheck does not include it"
)


class LabNotInstalled(TransportUnavailable):
    pass


def known_flaws() -> list[str]:
    try:
        from tenantlab.lab.vulnerable import Flaw  # noqa: PLC0415
    except ImportError:
        raise LabNotInstalled(NOT_INSTALLED) from None
    return sorted(f.name for f in Flaw)


class LabFiles(NamedTuple):
    database: Path  # the working database the lab serves
    pristine: Path  # an untouched copy taken right after seeding


class LabFixtureTransport:
    """The lab in process. It is STATE-AWARE: it reads the lab's database with raw SQL, independently
    of the lab's own code, and can restore a pristine copy, so write checks are safe here and only here."""

    state_aware = True

    def __init__(self, client: httpx.AsyncClient, tokens: dict[str, str], name: str, cap: int, files: LabFiles) -> None:
        self._client = client
        self._tokens = tokens
        self.name = name
        self._cap = cap
        self._files = files

    async def snapshot(self) -> Snapshot:
        return snapshot_sqlite(self._files.database)

    async def reset_state(self) -> None:
        """Copy the pristine database back over the working one (SQLite's backup API)."""
        try:
            source = sqlite3.connect(f"{self._files.pristine.resolve().as_uri()}?mode=ro", uri=True)
            try:
                target = sqlite3.connect(self._files.database)
                try:
                    source.backup(target)
                finally:
                    target.close()
            finally:
                source.close()
        except sqlite3.Error:
            raise SnapshotError("the pristine state could not be restored") from None

    def __repr__(self) -> str:
        return f"LabFixtureTransport({self.name!r})"

    @classmethod
    def open(cls, config: Config, *, variant: str | None = None, flaws: Iterable[str] | None = None) -> Any:
        return _open(cls, config, variant, None if flaws is None else tuple(flaws))

    def has_credential(self, principal: str | None) -> bool:
        return principal is None or principal in self._tokens

    def secrets(self) -> list[str]:
        return list(self._tokens.values())

    async def send(self, method: str, path: str, principal: str | None, body: bytes | None = None) -> Observation:
        if method not in (*READ_METHODS, *WRITE_METHODS):
            raise PolicyRefusal(f"method {method[:10]!r} is not allowed")
        if body is not None and method not in WRITE_METHODS:
            raise PolicyRefusal("a request body is only allowed on a write")
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if principal is not None:
            if principal not in self._tokens:
                raise PolicyRefusal("no credential for this principal")
            headers["Authorization"] = f"Bearer {self._tokens[principal]}"
        response = await self._client.request(method, path, headers=headers, content=body)
        seen = {k.lower(): v for k, v in response.headers.items()}
        if len(response.content) > self._cap:
            return Observation(status=response.status_code, headers=seen, error="body_too_large")
        return Observation(status=response.status_code, headers=seen, body=response.content)

    async def aclose(self) -> None:
        await self._client.aclose()


def _mint_tokens(config: Config, fixtures: Any, private: Any) -> dict[str, str]:
    """One short-lived token per principal that names a fixture, signed with the run's ephemeral key."""
    import jwt  # noqa: PLC0415

    now = int(time.time())
    tokens: dict[str, str] = {}
    for key, principal in config.principals.items():
        if principal.credential is not None and principal.credential.fixture is not None:
            claims = {
                "sub": fixtures.principal(principal.credential.fixture).id, "jti": str(uuid.uuid4()),
                "iss": ISSUER, "aud": AUDIENCE, "iat": now, "nbf": now, "exp": now + 600,
            }  # fmt: skip
            tokens[key] = jwt.encode(claims, private, algorithm="EdDSA")
    return tokens


def _copy_database(source: Path, target: Path) -> None:
    origin = sqlite3.connect(source)
    try:
        destination = sqlite3.connect(target)
        try:
            origin.backup(destination)
        finally:
            destination.close()
    finally:
        origin.close()


@asynccontextmanager
async def _open(
    cls: type[LabFixtureTransport],
    config: Config,
    variant: str | None,
    flaws: tuple[str, ...] | None,
) -> AsyncIterator[LabFixtureTransport]:
    ref = config.scope.target.fixture
    if ref is None:
        raise TransportUnavailable("the config has no scope.target.fixture, which the fixture transport needs")
    variant = variant or ref.variant
    chosen = tuple(ref.flaws) if flaws is None else flaws
    if variant not in ("patched", "vulnerable"):
        raise TransportUnavailable("fixture variant must be 'patched' or 'vulnerable'")
    if chosen and variant != "vulnerable":
        raise TransportUnavailable("flaws can only be enabled on the 'vulnerable' variant")
    try:
        import jwt  # noqa: F401, PLC0415 - a presence check: the helper that mints tokens imports it
        from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: PLC0415
        from tenantlab.api.app import create_app  # noqa: PLC0415
        from tenantlab.config import Settings  # noqa: PLC0415
        from tenantlab.db.migrate import upgrade_to_head  # noqa: PLC0415
        from tenantlab.db.seed import seed_fixtures  # noqa: PLC0415
        from tenantlab.lab.fixtures.loader import load_fixtures  # noqa: PLC0415
    except ImportError:
        raise LabNotInstalled(NOT_INSTALLED) from None
    unknown = sorted(set(chosen) - set(known_flaws()))
    if unknown:
        raise TransportUnavailable(f"unknown flaw name(s): {', '.join(u[:40] for u in unknown)}")

    private = Ed25519PrivateKey.generate()  # ephemeral: never written anywhere
    public_pem = (
        private.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode("ascii")
    )
    with tempfile.TemporaryDirectory(prefix="boundarycheck-lab-") as scratch:
        database = Path(scratch) / "lab.sqlite"
        pristine = Path(scratch) / "pristine.sqlite"
        url = f"sqlite+pysqlite:///{database}"
        upgrade_to_head(url)
        seed_fixtures(url)
        _copy_database(database, pristine)
        settings = Settings(
            database_url=url,
            jwt_issuer=ISSUER,
            jwt_audience=AUDIENCE,
            jwt_public_key_pem=public_pem,
        )
        if variant == "patched":
            app = create_app(settings)
            name = "fixture:tenant-boundary-lab:patched"
        else:
            from tenantlab.lab.vulnerable import Flaw, create_vulnerable_app  # noqa: PLC0415

            app = create_vulnerable_app(settings, flaws=frozenset(Flaw[n] for n in chosen), environ=LAB_ENV)
            name = f"fixture:tenant-boundary-lab:vulnerable({','.join(chosen) or 'no flaws'})"
        tokens = _mint_tokens(config, load_fixtures(), private)
        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://lab.invalid")
        transport = cls(client, tokens, name, config.scope.target.max_response_bytes, LabFiles(database, pristine))
        try:
            yield transport
        finally:
            await transport.aclose()
