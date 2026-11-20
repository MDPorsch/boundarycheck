"""OpenAPI import: a SKELETON config from an OpenAPI 3 document (docs/design-v0.3.md s5).

The document is UNTRUSTED input (you did not write it). So: a size cap before parsing, no YAML aliases or
anchors, a depth cap, local `$ref` only (never fetched, never a file), a cycle guard and a work cap; no
network and no file other than the one the caller names; and nothing from the document reaches the output
unless it fits the config's own strict alphabets, so it cannot inject YAML. The output is parsed by the real
config loader before it is returned.

It never writes the POLICY. A policy derived from the thing it judges is not independent, so every capability
is `[]` (nobody may) and every field needs the highest role: a run before a person edits it fails loudly.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Final

import yaml

from boundarycheck.config import (
    FIELD_PATH_PATTERN,
    IDENT_PATTERN,
    PARAM_PATTERN,
    PATH_RE,
    ConfigError,
    _StrictLoader,
    parse_config,
)
from boundarycheck.credentials import COOKIE_NAME, FORBIDDEN_HEADERS, HEADER_NAME

MAX_SPEC_BYTES: Final = 4 * 1024 * 1024
MAX_OPERATIONS: Final = 500
MAX_NODES: Final = 400_000
MAX_REF_CHAIN: Final = 8
MAX_FIELD_DEPTH: Final = 4
MAX_FIELDS_PER_ACTION: Final = 100
MAX_DEPTH: Final = 64
MAX_NOTES: Final = 40
ROLES: Final = ["viewer", "editor", "admin", "owner"]
READ_METHODS: Final = ("get", "head")
WRITE_METHODS: Final = ("post", "put", "patch", "delete", "options", "trace")
_PRINTABLE: Final = re.compile(r"[^\x20-\x7e]+")
_SEGMENT: Final = re.compile(r"[A-Za-z0-9._~-]+")
_PARAM_SEGMENT: Final = re.compile(r"\{([^{}/]{1,64})\}")


class OpenApiError(Exception):
    """The document could not be imported. The message is safe to show."""


class _SpecLoader(_StrictLoader):
    max_depth = MAX_DEPTH


@dataclass
class ImportResult:
    yaml_text: str
    notes: list[str] = field(default_factory=list)
    actions: int = 0
    skipped: int = 0  # operations that are not GET or HEAD


def _safe(text: object, limit: int = 80) -> str:
    """Printable ASCII only, for anything that goes into a comment or a note."""
    return _PRINTABLE.sub(" ", str(text)).strip()[:limit]


class _Walk:
    def __init__(self, root: dict[str, Any]) -> None:
        self.root = root
        self.nodes = 0
        self.notes: list[str] = []

    def note(self, text: str) -> None:
        if len(self.notes) < MAX_NOTES:
            self.notes.append(text)

    def tick(self) -> None:
        self.nodes += 1
        if self.nodes > MAX_NODES:
            raise OpenApiError("the document is too complex to import")

    def resolve(self, node: Any, where: str) -> Any:
        """Follow local `$ref`s to a real node. External references are refused, never fetched."""
        seen: set[str] = set()
        while isinstance(node, dict) and "$ref" in node:
            self.tick()
            ref = node["$ref"]
            if not isinstance(ref, str) or not ref.startswith("#/"):
                self.note(f"{where}: an external or non-local $ref was not followed (only '#/...' references are read)")
                return None
            if ref in seen or len(seen) >= MAX_REF_CHAIN:
                return None
            seen.add(ref)
            target: Any = self.root
            for raw_part in ref[2:].split("/"):
                part = raw_part.replace("~1", "/").replace("~0", "~")
                if not isinstance(target, dict) or part not in target:
                    self.note(f"{where}: the $ref '{_safe(ref, 60)}' points at something that is not in the document")
                    return None
                target = target[part]
            node = target
        return node


def _parse(raw: bytes | str) -> dict[str, Any]:
    data = raw.encode("utf-8", errors="replace") if isinstance(raw, str) else raw
    if len(data) > MAX_SPEC_BYTES:
        raise OpenApiError(f"the document is too large (limit {MAX_SPEC_BYTES // (1024 * 1024)} MiB)")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise OpenApiError("the document is not valid UTF-8 text") from None
    try:
        if text.lstrip().startswith("{"):
            loaded: Any = json.loads(text)
        else:
            loader = _SpecLoader(text)
            try:
                loaded = loader.get_single_data()
            finally:
                loader.dispose()
    except ConfigError as exc:
        raise OpenApiError(str(exc)) from None
    except (ValueError, yaml.YAMLError):
        raise OpenApiError("the document is not valid JSON or YAML") from None
    except RecursionError:
        raise OpenApiError("the document is nested too deeply") from None
    if not isinstance(loaded, dict):
        raise OpenApiError("the document must be an OpenAPI object at the top level")
    _check_depth(loaded)
    return loaded


def _check_depth(value: Any) -> None:
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > MAX_DEPTH:
            raise OpenApiError(f"the document is nested too deeply (more than {MAX_DEPTH} levels)")
        children = node.values() if isinstance(node, dict) else node if isinstance(node, list) else ()
        stack.extend((child, depth + 1) for child in children)


def _snake(name: str) -> str | None:
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).replace("-", "_").replace(".", "_").lower()
    return text if re.fullmatch(PARAM_PATTERN, text) else None


def _convert(path: str) -> tuple[str, list[str]] | str:
    """(template, params) for the config, or the reason this path cannot be held."""
    if not isinstance(path, str) or not path.startswith("/") or len(path) > 256:
        return "the path is not a plain '/...' path of at most 256 characters"
    if path == "/":
        return "/", []
    out: list[str] = []
    params: list[str] = []
    for segment in path[1:].split("/"):
        if segment in {"", ".", ".."}:
            return "the path has an empty, '.' or '..' segment"
        match = _PARAM_SEGMENT.fullmatch(segment)
        if match is not None:
            name = _snake(match.group(1))
            if name is None or name in params:
                return "a path parameter name does not fit the config (letters, digits and _)"
            params.append(name)
            out.append("{" + name + "}")
        elif _SEGMENT.fullmatch(segment):
            out.append(segment)
        else:
            return "a path segment has characters the config does not allow (only letters, digits, . _ ~ -, or one {parameter})"
    template = "/" + "/".join(out)
    return (template, params) if PATH_RE.fullmatch(template) else "the path does not fit the config's path rules"


def _kind(template: str, params: list[str]) -> str:
    if not params:
        return "root"
    last = params[-1]
    base = last[:-3] if last.endswith("_id") else ("" if last == "id" else last)
    if not base:  # `/projects/{id}`: name the kind after the segment before the parameter
        before = template.split("{" + last + "}", maxsplit=1)[0].rstrip("/").rsplit("/", 1)[-1]
        base = _snake(before) or "item"
        base = base[:-3] + "y" if base.endswith("ies") else base[:-1] if base.endswith("s") and len(base) > 3 else base
    return base if re.fullmatch(PARAM_PATTERN, base) else "item"


def _action_id(operation_id: Any, method: str, template: str, params: list[str], used: set[str]) -> str:
    if isinstance(operation_id, str) and re.fullmatch(IDENT_PATTERN, operation_id):
        candidate = operation_id
    else:
        slug = (
            ".".join(
                ("by_" + p) if "{" + p + "}" in template.split("/") else s
                for s in template.split("/")[1:]
                for p in [s.strip("{}")]
            )
            or "root"
        )
        slug = re.sub(r"[^a-z0-9_.-]", "-", slug.lower())[:100]
        candidate = f"{method}.{slug}".strip(".")
        if not re.fullmatch(IDENT_PATTERN, candidate):
            candidate = f"{method}.operation"
    unique, n = candidate, 2
    while unique in used:
        unique = f"{candidate}-{n}"
        n += 1
    used.add(unique)
    return unique


def _schema_props(walk: _Walk, schema: Any, where: str) -> dict[str, Any]:
    """The properties of an object schema, merging allOf, oneOf and anyOf members."""
    resolved = walk.resolve(schema, where)
    if not isinstance(resolved, dict):
        return {}
    props: dict[str, Any] = {}
    own = resolved.get("properties")
    if isinstance(own, dict):
        props.update({k: v for k, v in own.items() if isinstance(k, str)})
    for combinator in ("allOf", "oneOf", "anyOf"):
        members = resolved.get(combinator)
        if isinstance(members, list):
            for member in members[:20]:
                for k, v in _schema_props(walk, member, where).items():
                    props.setdefault(k, v)
    return props


def _field_paths(  # noqa: PLR0913, PLR0917 - the walk state travels with the recursion
    walk: _Walk, schema: Any, where: str, prefix: str = "", depth: int = 0, stack: tuple[int, ...] = ()
) -> list[str]:
    walk.tick()
    resolved = walk.resolve(schema, where)
    if not isinstance(resolved, dict) or id(resolved) in stack or depth > MAX_FIELD_DEPTH:
        return []
    out: list[str] = []
    for name, sub in _schema_props(walk, resolved, where).items():
        path = f"{prefix}.{name}" if prefix else name
        if not re.fullmatch(FIELD_PATH_PATTERN, path):
            walk.note(f"{where}: a property name does not fit the config's alphabet and was skipped")
            continue
        out.append(path)
        child = walk.resolve(sub, where)
        if not isinstance(child, dict):
            continue
        if isinstance(child.get("items"), (dict,)):
            out += _field_paths(walk, child["items"], where, f"{path}[]", depth + 1, (*stack, id(resolved)))
        else:
            out += _field_paths(walk, child, where, path, depth + 1, (*stack, id(resolved)))
    return out


def _response_schema(walk: _Walk, operation: dict[str, Any], where: str) -> Any:
    responses = operation.get("responses")
    if not isinstance(responses, dict):
        return None
    for code in sorted(str(k) for k in responses):
        if not code.startswith("2"):
            continue
        response = walk.resolve(responses.get(code, responses.get(int(code)) if code.isdigit() else None), where)
        content = response.get("content") if isinstance(response, dict) else None
        if isinstance(content, dict):
            for media, body in content.items():
                if isinstance(media, str) and "json" in media.lower() and isinstance(body, dict):
                    return body.get("schema")
    return None


def _credential_scheme(walk: _Walk) -> tuple[dict[str, str], str]:  # noqa: PLR0911 - one answer per scheme kind
    """(credential settings for a principal, env-name stem) from the document's security schemes."""
    schemes = (
        walk.root.get("components", {}).get("securitySchemes")
        if isinstance(walk.root.get("components"), dict)
        else None
    )
    if not isinstance(schemes, dict) or not schemes:
        return {}, "TOKEN"
    wanted: list[str] = []
    security = walk.root.get("security")
    if isinstance(security, list):
        for requirement in security:
            if isinstance(requirement, dict):
                wanted += [k for k in requirement if isinstance(k, str)]
    chosen = next((schemes[k] for k in wanted if k in schemes), None) or (
        next(iter(schemes.values())) if len(schemes) == 1 else None
    )
    if not isinstance(chosen, dict):
        return {}, "TOKEN"
    kind = str(chosen.get("type", "")).lower()
    if kind in {"oauth2", "openidconnect"} or (kind == "http" and str(chosen.get("scheme", "")).lower() == "bearer"):
        return {}, "TOKEN"
    if kind == "http":
        walk.note(
            "the document uses HTTP Basic or another scheme that is not supported; a bearer credential was assumed"
        )
        return {}, "TOKEN"
    if kind == "apikey":
        where, name = str(chosen.get("in", "")).lower(), chosen.get("name")
        if (
            where == "header"
            and isinstance(name, str)
            and HEADER_NAME.fullmatch(name)
            and name.lower() not in FORBIDDEN_HEADERS
        ):
            return {"in": "header", "name": name}, "KEY"
        if where == "cookie" and isinstance(name, str) and COOKIE_NAME.fullmatch(name):
            return {"in": "cookie", "name": name}, "COOKIE"
        walk.note(
            f"an API key in '{_safe(where, 20)}' (or with an unusable name) is not supported "
            "(a key in a URL ends up in logs); a bearer credential was assumed"
        )
        return {}, "TOKEN"
    return {}, "TOKEN"


def _placeholder(param: str, tag: str) -> str:
    return f"REPLACE-WITH-{param.upper().replace('_', '-')}-{tag}"[:120]


def import_openapi(raw: bytes | str) -> ImportResult:  # noqa: PLR0912, PLR0915 - one straight pass over the document
    document = _parse(raw)
    if "swagger" in document:
        raise OpenApiError("Swagger 2.0 is not supported; convert the document to OpenAPI 3 first")
    version = document.get("openapi")
    if not isinstance(version, str) or not version.startswith("3."):
        raise OpenApiError("this is not an OpenAPI 3.x document (no 'openapi: 3.x' field)")
    paths = document.get("paths")
    if not isinstance(paths, dict):
        raise OpenApiError("the document has no 'paths' object")
    walk = _Walk(document)
    used: set[str] = set()
    actions: list[dict[str, Any]] = []
    fields: dict[str, dict[str, str]] = {}
    capabilities: dict[str, list[str]] = {}
    kinds: dict[str, set[str]] = {}
    skipped = 0
    skipped_names: list[str] = []
    capped = False
    for path in sorted(p for p in paths if isinstance(p, str)):
        item = paths[path]
        if not isinstance(item, dict):
            continue
        for method in WRITE_METHODS:
            if isinstance(item.get(method), dict):
                skipped += 1
                if len(skipped_names) < 5:
                    skipped_names.append(f"{method.upper()} {_safe(item[method].get('operationId', path), 40)}")
        for method in READ_METHODS:
            operation = item.get(method)
            if not isinstance(operation, dict):
                continue
            if len(actions) >= MAX_OPERATIONS:
                capped = True
                continue
            walk.tick()
            converted = _convert(path)
            if isinstance(converted, str):
                walk.note(f"skipped {method.upper()} {_safe(path, 60)}: {converted}")
                continue
            template, params = converted
            action_id = _action_id(operation.get("operationId"), method, template, params, used)
            kind = _kind(template, params)
            kinds.setdefault(kind, set()).update(params)
            where = f"{method.upper()} {_safe(path, 50)}"
            schema = _response_schema(walk, operation, where)
            paths_found = (
                list(dict.fromkeys(_field_paths(walk, schema, where)))[:MAX_FIELDS_PER_ACTION]
                if schema is not None
                else []
            )
            action: dict[str, Any] = {
                "id": action_id,
                "method": method.upper(),
                "path": template,
                "resource_kind": kind,
                "surface": action_id,
            }
            top = _schema_props(walk, schema, where) if schema is not None else {}
            items = walk.resolve(top.get("items"), where) if "items" in top else None
            if isinstance(items, dict) and items.get("type") == "array":
                action["page"] = True
            actions.append(action)
            capabilities[action_id] = []
            fields[action_id] = dict.fromkeys(paths_found, "owner")
    if capped:
        walk.note(f"only the first {MAX_OPERATIONS} operations were imported")
    if skipped:
        walk.note(
            f"{skipped} write operation(s) were not imported (writes run only on the fixture): {', '.join(skipped_names)}"
        )
    if not actions:
        raise OpenApiError("the document has no GET or HEAD operation the config can hold")
    credential, stem = _credential_scheme(walk)
    resources: list[dict[str, Any]] = []
    for kind in sorted(kinds):
        for suffix, tenant in (("a", "A"), ("b", "B"), ("missing", None)):
            entry: dict[str, Any] = {"key": f"{kind}-{suffix}", "kind": kind}
            if tenant is not None:
                entry["tenant"] = tenant
            else:
                entry["exists"] = False
            entry["ids"] = {p: _placeholder(p, tenant or "THAT-DOES-NOT-EXIST") for p in sorted(kinds[kind])}
            resources.append(entry)
    raw_info = document.get("info")
    info: dict[str, Any] = raw_info if isinstance(raw_info, dict) else {}
    title = _safe(info.get("title", "api"), 60) or "api"
    raw_servers = document.get("servers")
    server_list: list[Any] = raw_servers[:3] if isinstance(raw_servers, list) else []
    servers = [_safe(s.get("url"), 100) for s in server_list if isinstance(s, dict)]
    data: dict[str, Any] = {
        "version": 1,
        "scope": {"id": "openapi-import", "target": {"label": title, "base_url": "http://127.0.0.1:8000", "request_budget": 500, "rate_limit_rps": 10}},
        "tenants": [{"key": "A", "state": "active"}, {"key": "B", "state": "active"}],
        "principals": {
            name: {"label": label, "credential": {"env": f"BC_{stem}_{name.upper()}", **credential}}
            for name, label in (("alice", "tenant A owner"), ("bob", "tenant A viewer"), ("carol", "tenant B owner"))
        },
        "memberships": [
            {"principal": "alice", "tenant": "A", "role": "owner", "status": "active"},
            {"principal": "bob", "tenant": "A", "role": "viewer", "status": "active"},
            {"principal": "carol", "tenant": "B", "role": "owner", "status": "active"},
        ],
        "resources": resources,
        "actions": actions,
        "policy": {
            "roles": ROLES, "hidden_is_not_found": True, "capabilities": capabilities, "fields": fields,
            "concealment": {"ignore_body_fields": ["request_id"]},
        },
        "redaction": {"mask_fields": []},
    }  # fmt: skip
    header = [
        f"# boundarycheck config generated from an OpenAPI document ({title}, version {_safe(info.get('version', '?'), 30)}).",
        "# THIS IS A SKELETON. It knows the shape of the API, not who may see what.",
        "# EDIT BEFORE YOU RUN IT. The POLICY is yours to write, from your requirements, not from this document:",
        "#   - policy.capabilities: every action is [] (nobody may). List the roles that may call each one.",
        "#   - policy.fields: every field needs the 'owner' role. Lower each to the minimum role that may see it.",
        "#   - tenants, principals, memberships, resources: replace the placeholders with your test data.",
        "#   - scope.target.base_url: set it yourself. A remote host also needs allowed_hosts and an authorization",
        "#     block (docs/remote-live-design.md); this tool never fills in a remote address for you.",
        "# Until you do, a run reports findings on purpose: it fails loudly instead of passing by accident.",
    ]
    if servers:
        header.append(f"# The document names these servers (not used): {', '.join(servers)}")
    header += [f"# note: {_safe(n, 160)}" for n in walk.notes]
    text = (
        "\n".join(header)
        + "\n"
        + yaml.safe_dump(data, sort_keys=False, default_flow_style=False, width=100, allow_unicode=False)
    )
    try:
        parse_config(text)
    except ConfigError as exc:
        raise OpenApiError(f"the generated config did not validate (this is a bug in the importer): {exc}") from None
    return ImportResult(yaml_text=text, notes=list(walk.notes), actions=len(actions), skipped=skipped)
