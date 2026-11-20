"""The hardened config loader and its strict schema (docs/contract.md s6).

This is the only place user-controlled structure is parsed, so it is deliberately paranoid:
size cap before parsing, `safe_load` semantics with no tags, aliases/anchors/merge keys refused,
duplicate keys refused, nesting capped, strict types (no coercion), every identifier validated.
Errors name a location and a problem and never echo the offending value.
"""

from __future__ import annotations

import json
import re
import unicodedata
from datetime import datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, Final, Literal

import yaml
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

from boundarycheck.credentials import COOKIE_NAME, FORBIDDEN_HEADERS, HEADER_NAME, PREFIX, Scheme
from boundarycheck.netcheck import (
    AddressRefused,
    NotLoopback,
    check_address,
    parse_address,
    parse_target_url,
    validate_networks,
)

MAX_CONFIG_BYTES: Final = 256 * 1024
MAX_DEPTH: Final = 32
ANONYMOUS: Final = "anonymous"

IDENT_PATTERN: Final = r"^[A-Za-z0-9_-][A-Za-z0-9._~-]{0,127}$"
PARAM_PATTERN: Final = r"^[a-z_][a-z0-9_]{0,63}$"
ENV_PATTERN: Final = r"^[A-Z_][A-Z0-9_]{0,63}$"
_SEGMENT: Final = r"(?:[A-Za-z0-9._~-]+|\{[a-z_][a-z0-9_]{0,63}\})"
_PATH_RE: Final = re.compile(rf"^/(?:{_SEGMENT}(?:/{_SEGMENT})*)?$")  # "/" alone is the root path
PATH_RE: Final = _PATH_RE  # the alphabet of a request path, shared with the OpenAPI importer
_PARAM_RE: Final = re.compile(r"\{([a-z_][a-z0-9_]{0,63})\}")
FIELD_PATH_PATTERN: Final = r"^[A-Za-z0-9_.\[\]-]{1,120}$"

Ident = Annotated[str, StringConstraints(pattern=IDENT_PATTERN)]
Param = Annotated[str, StringConstraints(pattern=PARAM_PATTERN)]
EnvName = Annotated[str, StringConstraints(pattern=ENV_PATTERN)]
FieldPath = Annotated[str, StringConstraints(pattern=FIELD_PATH_PATTERN)]
Label = Annotated[str, StringConstraints(max_length=200)]


class ConfigError(ValueError):
    """The config could not be loaded. The message is safe to show: it never contains input values."""


# ------------------------------------------------------------------------------ YAML layer ----
class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that refuses aliases, anchors, merge keys, duplicate keys and deep nesting."""

    max_depth: int = MAX_DEPTH

    def __init__(self, stream: str) -> None:
        super().__init__(stream)
        self._depth = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.events.AliasEvent):
            raise ConfigError("YAML aliases are not allowed (an alias can expand into a denial of service)")
        if getattr(self.peek_event(), "anchor", None) is not None:  # type: ignore[no-untyped-call]
            raise ConfigError("YAML anchors (and the aliases that use them) are not allowed")
        self._depth += 1
        if self._depth > self.max_depth:
            raise ConfigError(f"the document is nested too deeply (more than {self.max_depth} levels)")
        try:
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1

    def construct_mapping(self, node: Any, deep: bool = False) -> dict[Any, Any]:
        seen: set[Any] = set()
        for key_node, _value_node in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                raise ConfigError("YAML merge keys ('<<') are not allowed")
            key = self.construct_object(key_node, deep=True)
            try:
                hash(key)
            except TypeError:
                raise ConfigError("a mapping key is not a plain value") from None
            if key in seen:
                shown = str(key)[:40]
                raise ConfigError(f"duplicate key '{shown}' (line {key_node.start_mark.line + 1})")
            seen.add(key)
        return super().construct_mapping(node, deep)


def _decode(raw: bytes) -> str:
    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigError(f"the config is too large (limit {MAX_CONFIG_BYTES // 1024} KiB)")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ConfigError("the config is not valid UTF-8 text") from None


def _load_yaml(text: str) -> Any:
    loader = _StrictLoader(text)
    try:
        return loader.get_single_data()
    except ConfigError:
        raise
    except yaml.MarkedYAMLError as exc:
        mark = exc.problem_mark
        where = f" at line {mark.line + 1}" if mark is not None else ""
        if isinstance(exc, yaml.composer.ComposerError) and "single document" in str(exc.context or ""):
            raise ConfigError("the config must contain exactly one YAML document") from None
        raise ConfigError(f"invalid YAML{where} (a syntax error or a construct that is not allowed)") from None
    except yaml.YAMLError:
        raise ConfigError("invalid YAML (could not be read)") from None
    finally:
        loader.dispose()


# -------------------------------------------------------------------------------- schema ----
class _Model(BaseModel):
    model_config = ConfigDict(
        extra="forbid", strict=True, frozen=True, hide_input_in_errors=True, populate_by_name=True
    )


KEYCHAIN_NAME: Final = r"^[A-Za-z0-9._@+-]{1,128}$"
KeychainName = Annotated[str, StringConstraints(pattern=KEYCHAIN_NAME)]


class Keychain(_Model):
    """A secret held in the operating system's keychain (docs/design-v0.3.md s3), named here, never stored."""

    service: KeychainName = "boundarycheck"
    username: KeychainName


class Credential(_Model):
    """A principal's credential is NAMED here, never stored: an environment variable (live) and/or a
    fixture key (the in-process lab adapter mints its own tokens)."""

    env: EnvName | None = None
    fixture: Ident | None = None
    keychain: Keychain | None = None
    # How the value is sent (docs/design-v0.3.md s2): a bearer token (default), an API key in a named
    # header, or a named session cookie. `in` is a Python keyword, hence the alias.
    scheme: Scheme = Field(default="bearer", alias="in")
    name: str | None = None
    prefix: str | None = None

    @model_validator(mode="after")
    def _names_something(self) -> Credential:  # noqa: PLR0912 - one flat list of independent rules
        if self.env is None and self.fixture is None and self.keychain is None:
            raise ValueError("a credential must name an environment variable (env), a keychain entry or a fixture key")
        if self.env is not None and self.keychain is not None:
            raise ValueError("a credential names an env variable or a keychain entry, not both")
        if self.scheme == "bearer":
            if self.name is not None or self.prefix is not None:
                raise ValueError(
                    "a bearer credential takes no name or prefix (they belong to in: header or in: cookie)"
                )
            return self
        if self.env is None and self.keychain is None:
            raise ValueError("in: header and in: cookie need an env variable or a keychain entry that holds the value")
        if self.name is None:
            raise ValueError(f"in: {self.scheme} needs a name (the header or cookie name)")
        if self.scheme == "header":
            if HEADER_NAME.fullmatch(self.name) is None:
                raise ValueError("a header name is letters, digits and hyphens, at most 64 characters")
            if self.name.lower() in FORBIDDEN_HEADERS:
                raise ValueError(
                    "this header name is not allowed: it changes how the request is framed or is set by the tool"
                )
            if self.prefix is not None and PREFIX.fullmatch(self.prefix) is None:
                raise ValueError("a prefix is 1 to 32 printable ASCII characters")
        else:
            if COOKIE_NAME.fullmatch(self.name) is None:
                raise ValueError("a cookie name is letters, digits, . _ and -, at most 64 characters")
            if self.prefix is not None:
                raise ValueError("a cookie credential takes no prefix")
        return self


class Principal(_Model):
    label: Label = ""
    status: Literal["active", "disabled"] = "active"
    credential: Credential | None = None


class Tenant(_Model):
    key: Ident
    state: Literal["active", "suspended"] = "active"
    allowed: dict[Param, list[Ident]] = Field(default_factory=dict)  # attribute -> permitted values


class Membership(_Model):
    principal: Ident
    tenant: Ident
    role: Ident
    status: Literal["active", "revoked"] = "active"


class Resource(_Model):
    key: Ident
    kind: Param
    tenant: Ident | None = None
    exists: bool = True
    attributes: dict[Param, Ident] = Field(default_factory=dict)
    ids: dict[Param, Ident] = Field(default_factory=dict)


class ListSpec(_Model):
    kind: Param
    id_key: Param
    item_id_field: Param = "id"
    total_field: Param | None = None


READ_METHODS: Final = ("GET", "HEAD")
WRITE_METHODS: Final = ("POST", "PUT", "PATCH", "DELETE")
MAX_BODY_BYTES: Final = 4096
MAX_BODY_DEPTH: Final = 6


def _depth(value: Any) -> int:
    if isinstance(value, dict):
        return 1 + max((_depth(v) for v in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((_depth(v) for v in value), default=0)
    return 0


class Action(_Model):
    id: Ident
    # Reads run anywhere. A write is only ever sent by a state-aware transport (the in-process
    # fixture) and only where the policy says it must be refused (docs/contract.md s9).
    method: Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]
    path: str
    resource_kind: Param
    surface: Ident
    capability: Ident | None = None
    page: bool = False
    list_spec: ListSpec | None = Field(default=None, alias="list")
    body: dict[str, Any] | None = None  # a static JSON object; only for writes

    @field_validator("body")
    @classmethod
    def _plain_small_json(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is None:
            return value
        try:
            encoded = json.dumps(value, separators=(",", ":"))
        except (TypeError, ValueError):
            raise ValueError(
                "body must be plain JSON data (strings, numbers, booleans, null, lists, objects)"
            ) from None
        if len(encoded.encode("utf-8")) > MAX_BODY_BYTES:
            raise ValueError(f"body is too large (limit {MAX_BODY_BYTES} bytes)")
        if _depth(value) > MAX_BODY_DEPTH:
            raise ValueError(f"body is nested too deeply (limit {MAX_BODY_DEPTH} levels)")
        return value

    @model_validator(mode="after")
    def _body_only_on_writes(self) -> Action:
        if self.body is not None and not self.is_write:
            raise ValueError("a body is only allowed on a write action (POST, PUT, PATCH, DELETE)")
        return self

    @property
    def is_write(self) -> bool:
        return self.method in WRITE_METHODS

    @field_validator("path")
    @classmethod
    def _safe_path(cls, value: str) -> str:
        if len(value) > 256 or not _PATH_RE.fullmatch(value):
            raise ValueError("path must be '/' or '/segment/{param}/...' using only letters, digits and . _ ~ -")
        if any(part in {".", ".."} for part in value.split("/")):
            raise ValueError("path must not contain '.' or '..' segments")
        return value

    @property
    def params(self) -> list[str]:
        return _PARAM_RE.findall(self.path)

    @property
    def paged(self) -> bool:
        return self.page or self.list_spec is not None

    @property
    def cap(self) -> str:
        return self.capability or self.id


class Concealment(_Model):
    ignore_body_fields: list[Param] = Field(default_factory=list)


class Policy(_Model):
    roles: list[Ident] = Field(min_length=1)
    hidden_is_not_found: bool = True
    capabilities: dict[Ident, list[Ident]]
    fields: dict[Ident, dict[FieldPath, Ident]]  # surface -> field path -> minimum role
    concealment: Concealment = Field(default_factory=Concealment)


class Redaction(_Model):
    mask_fields: list[Param] = Field(default_factory=list)


class FixtureRef(_Model):
    adapter: Literal["tenant-boundary-lab"]
    variant: Literal["patched", "vulnerable"] = "patched"
    flaws: list[Ident] = Field(default_factory=list)


REMOTE_DEFAULT_RPS: Final = 2.0
REMOTE_MAX_RPS: Final = 20.0
MAX_WINDOW_DAYS: Final = 366
_HOST_ENTRY: Final = re.compile(
    r"^(?P<host>[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*"
    r"|\[[0-9a-f:.]{2,45}\])(?::(?P<port>[0-9]{1,5}))?$"
)


def _declared(entry: str) -> tuple[str, int]:
    """(host, port) of one `allowed_hosts` entry: an exact lowercase ASCII name or IP literal."""
    found = _HOST_ENTRY.fullmatch(entry) if len(entry) <= 260 else None
    if found is None:
        raise ValueError(
            "allowed_hosts entries are exact lowercase ASCII host names or IP literals, "
            "with an optional :port (no wildcards, no trailing dot, xn-- form for international names)"
        )
    host = found["host"]
    if host.startswith("["):
        host = host[1:-1]
    port = int(found["port"]) if found["port"] else 443
    if not 1 <= port <= 65535:
        raise ValueError("allowed_hosts port is out of range")
    return host, port


class Target(_Model):
    label: Label
    fixture: FixtureRef | None = None
    base_url: str | None = None
    request_budget: int = Field(default=500, ge=1, le=100_000)
    rate_limit_rps: float = Field(default=10.0, gt=0, le=1000)
    timeout_seconds: float = Field(default=10.0, gt=0, le=300)
    max_response_bytes: int = Field(default=1_048_576, ge=1024, le=16 * 1024 * 1024)
    # Remote live mode (docs/remote-live-design.md). All three are ignored for a loopback target.
    allowed_hosts: list[str] = Field(default_factory=list)
    allowed_networks: list[str] = Field(default_factory=list)
    ca_bundle: Annotated[str, StringConstraints(min_length=1, max_length=512)] | None = None

    @field_validator("base_url")
    @classmethod
    def _well_formed(cls, value: str | None) -> str | None:
        if value is not None:
            try:
                parse_target_url(value)
            except NotLoopback as exc:
                raise ValueError(str(exc)) from None
        return value

    @field_validator("allowed_networks")
    @classmethod
    def _networks(cls, value: list[str]) -> list[str]:
        try:
            return validate_networks(value)
        except ValueError as exc:
            raise ValueError(f"allowed_networks: {exc}") from None

    @property
    def is_remote(self) -> bool:
        return self.base_url is not None and parse_target_url(self.base_url)[3]

    @property
    def effective_rate_limit_rps(self) -> float:
        """A remote host is asked gently unless the operator says otherwise (and never faster than 20/s)."""
        if self.is_remote and "rate_limit_rps" not in self.model_fields_set:
            return REMOTE_DEFAULT_RPS
        return self.rate_limit_rps

    @model_validator(mode="after")
    def _remote_is_fully_declared(self) -> Target:
        if self.base_url is None or not self.is_remote:
            return self
        _scheme, host, port, _remote = parse_target_url(self.base_url)
        if len(self.allowed_hosts) != 1:
            raise ValueError(
                "a remote base_url needs allowed_hosts with exactly one entry, the same host "
                "(and port, if it is not 443) as base_url"
                if not self.allowed_hosts or len(self.allowed_hosts) > 1
                else "allowed_hosts"
            )
        declared_host, declared_port = _declared(self.allowed_hosts[0])
        if (declared_host, declared_port) != (host, port):
            raise ValueError("allowed_hosts must name exactly the host and port of base_url")
        try:
            parse_address(host)
        except AddressRefused:
            pass  # a name: its addresses are checked when it is resolved, at run time
        else:
            try:
                check_address(host, self.allowed_networks)
            except AddressRefused as exc:
                raise ValueError(f"base_url: {exc}") from None
        if "rate_limit_rps" in self.model_fields_set and self.rate_limit_rps > REMOTE_MAX_RPS:
            raise ValueError(f"rate_limit_rps for a remote target may be at most {REMOTE_MAX_RPS:g} per second")
        return self


def _plain_text(value: str) -> str:
    if value != value.strip() or not value:
        raise ValueError("must be plain text without leading or trailing space")
    if any(unicodedata.category(ch) in {"Cc", "Cf", "Zl", "Zp"} for ch in value):
        raise ValueError("must not contain control, formatting or line-separator characters")
    return value


def _iso_timestamp(value: Any) -> Any:
    """YAML turns an unquoted timestamp into a datetime; a quoted one stays text, so accept ISO 8601 text
    too. Anything else (a date, a number, 'tomorrow') is left for the strict type to refuse."""
    if isinstance(value, str):
        if len(value) > 40:
            raise ValueError("not an ISO 8601 timestamp")
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            raise ValueError("not an ISO 8601 timestamp") from None
    return value


Timestamp = Annotated[datetime, BeforeValidator(_iso_timestamp)]


class Authorization(_Model):
    """The operator's DECLARATION that the assessment is authorized. The tool cannot verify it."""

    engagement: Annotated[str, StringConstraints(min_length=1, max_length=120)]
    not_before: Timestamp | None = None
    not_after: Timestamp

    @field_validator("engagement")
    @classmethod
    def _engagement(cls, value: str) -> str:
        return _plain_text(value)

    @field_validator("not_before", "not_after")
    @classmethod
    def _zone(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("timestamps need a UTC offset, for example 2026-12-04T23:59:59Z")
        return value

    @model_validator(mode="after")
    def _window(self) -> Authorization:
        if self.not_before is not None:
            if self.not_before >= self.not_after:
                raise ValueError("not_before must be earlier than not_after")
            if self.not_after - self.not_before > timedelta(days=MAX_WINDOW_DAYS):
                raise ValueError(f"the authorization window may not be longer than {MAX_WINDOW_DAYS} days")
        return self


class Scope(_Model):
    id: Ident
    target: Target
    authorization: Authorization | None = None

    @model_validator(mode="after")
    def _remote_needs_authorization(self) -> Scope:
        if self.target.is_remote and self.authorization is None:
            raise ValueError("a remote target needs an authorization block (engagement and not_after)")
        return self


class Config(_Model):
    version: Literal[1]
    scope: Scope
    tenants: list[Tenant]
    principals: dict[Ident, Principal]
    memberships: list[Membership] = Field(default_factory=list)
    resources: list[Resource]
    actions: list[Action] = Field(min_length=1)
    policy: Policy
    redaction: Redaction = Field(default_factory=Redaction)

    @model_validator(mode="after")
    def _cross_references(self) -> Config:
        problems = _check(self)
        if problems:
            raise ValueError("; ".join(problems[:12]))
        return self


def _dupes(items: list[str]) -> list[str]:
    return sorted({i for i in items if items.count(i) > 1})


def _check(cfg: Config) -> list[str]:  # noqa: PLR0912 - one flat list of independent rules reads best
    out: list[str] = []
    roles = set(cfg.policy.roles)
    tenants = {t.key for t in cfg.tenants}
    if len(roles) != len(cfg.policy.roles):
        out.append("policy.roles must not repeat a role")
    if ANONYMOUS in cfg.principals:
        out.append(f"'{ANONYMOUS}' is reserved for the implicit unauthenticated principal")
    out += [f"duplicate tenant key '{d}'" for d in _dupes([t.key for t in cfg.tenants])]
    out += [f"duplicate resource key '{d}'" for d in _dupes([r.key for r in cfg.resources])]
    out += [f"duplicate action id '{d}'" for d in _dupes([a.id for a in cfg.actions])]
    out += [f"duplicate membership '{d}'" for d in _dupes([f"{m.principal}/{m.tenant}" for m in cfg.memberships])]
    for m in cfg.memberships:
        if m.principal not in cfg.principals:
            out.append(f"membership refers to unknown principal '{m.principal}'")
        if m.tenant not in tenants:
            out.append(f"membership refers to unknown tenant '{m.tenant}'")
        if m.role not in roles:
            out.append(f"membership uses unknown role '{m.role}'")
    for r in cfg.resources:
        if r.tenant is not None and r.tenant not in tenants:
            out.append(f"resource '{r.key}' refers to unknown tenant '{r.tenant}'")
        if not r.exists and r.tenant is not None:
            out.append(f"resource '{r.key}' does not exist (exists: false) so it must not name a tenant")
        if r.exists and r.tenant is None:
            out.append(f"resource '{r.key}' needs a tenant (or declare exists: false)")
    kinds: dict[str, list[Resource]] = {}
    for r in cfg.resources:
        kinds.setdefault(r.kind, []).append(r)
    for a in cfg.actions:
        of_kind = kinds.get(a.resource_kind, [])
        if not of_kind:
            out.append(f"action '{a.id}' refers to resource kind '{a.resource_kind}' which has no resources")
        for r in of_kind:
            out += [f"resource '{r.key}' lacks id '{p}' needed by action '{a.id}'" for p in a.params if p not in r.ids]
        if a.cap not in cfg.policy.capabilities:
            out.append(f"policy.capabilities has no entry for '{a.cap}' (declare [] to deny everyone)")
        if a.surface not in cfg.policy.fields:
            out.append(
                f"policy.fields has no entry for surface '{a.surface}' (an empty mapping means no field may be shown)"
            )
        if a.list_spec is not None:
            ls = a.list_spec
            members = kinds.get(ls.kind, [])
            if not members:
                out.append(f"action '{a.id}' lists kind '{ls.kind}' which has no resources")
            out += [
                f"list id_key '{ls.id_key}' is missing on resource '{r.key}'" for r in members if ls.id_key not in r.ids
            ]
    for cap, allowed in cfg.policy.capabilities.items():
        out += [f"capability '{cap}' names unknown role '{r}'" for r in allowed if r not in roles]
    for surface, fields in cfg.policy.fields.items():
        out += [f"fields for '{surface}' name unknown role '{r}'" for r in set(fields.values()) if r not in roles]
    return out


# ------------------------------------------------------------------------------ entry points ----
def _summarize(exc: ValidationError) -> str:
    parts = []
    for err in exc.errors(include_input=False, include_url=False)[:10]:
        where = ".".join(str(p) for p in err["loc"]) or "config"
        parts.append(f"{where}: {err['msg']}")
    more = exc.error_count() - len(parts)
    return "; ".join(parts) + (f"; (+{more} more)" if more > 0 else "")


def parse_config(text: str | bytes) -> Config:
    raw = text.encode("utf-8") if isinstance(text, str) else text
    data = _load_yaml(_decode(raw))
    if data is None:
        raise ConfigError("the config is empty")
    if not isinstance(data, dict):
        raise ConfigError("the config must be a mapping at the top level")
    try:
        return Config.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(_summarize(exc)) from None


def load_config(path: str | Path) -> Config:
    target = Path(path)
    try:
        if not target.is_file():
            raise ConfigError("the config path is not a readable file")
        if target.stat().st_size > MAX_CONFIG_BYTES:
            raise ConfigError(f"the config is too large (limit {MAX_CONFIG_BYTES // 1024} KiB)")
        with target.open("rb") as handle:
            raw = handle.read(MAX_CONFIG_BYTES + 1)
    except OSError:
        raise ConfigError("the config file could not be read") from None
    return parse_config(raw)
