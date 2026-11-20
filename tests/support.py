"""Helpers shared by the tests. Nothing here imports product code at module level, so that a missing
module fails the CALLING test with an explicit message (a red test), never the whole collection."""

from __future__ import annotations

import contextlib
import copy
import gzip
import json
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "lab.yaml"
VULN_EXAMPLE = ROOT / "examples" / "lab-vulnerable.yaml"
LOOPBACK = "127.0.0.1"


def mini() -> dict[str, Any]:
    """A small, valid, hand-written config used by the unit tests."""
    return copy.deepcopy(
        {
            "version": 1,
            "scope": {
                "id": "unit",
                "target": {"label": "unit-target", "base_url": "http://127.0.0.1:9"},
            },
            "tenants": [
                {"key": "A", "state": "active", "allowed": {"market": ["UK"]}},
                {"key": "B", "state": "active", "allowed": {"market": ["US"]}},
                {"key": "C", "state": "suspended", "allowed": {"market": ["UK"]}},
            ],
            "principals": {
                "alice": {"credential": {"env": "BC_T_ALICE"}},
                "bob": {"credential": {"env": "BC_T_BOB"}},
                "carol": {"credential": {"env": "BC_T_CAROL"}},
                "gina": {"credential": {"env": "BC_T_GINA"}},
                "dis": {"status": "disabled", "credential": {"env": "BC_T_DIS"}},
                "frank": {"credential": {"env": "BC_T_FRANK"}},
            },
            "memberships": [
                {"principal": "alice", "tenant": "A", "role": "owner", "status": "active"},
                {"principal": "bob", "tenant": "A", "role": "viewer", "status": "active"},
                {"principal": "carol", "tenant": "B", "role": "owner", "status": "active"},
                {"principal": "gina", "tenant": "C", "role": "owner", "status": "active"},
                {"principal": "dis", "tenant": "A", "role": "editor", "status": "active"},
                {"principal": "frank", "tenant": "A", "role": "editor", "status": "revoked"},
            ],
            "resources": [
                {"key": "tA", "kind": "tenant", "tenant": "A", "ids": {"tenant_id": "ta"}},
                {"key": "tB", "kind": "tenant", "tenant": "B", "ids": {"tenant_id": "tb"}},
                {"key": "tC", "kind": "tenant", "tenant": "C", "ids": {"tenant_id": "tc"}},
                {"key": "tX", "kind": "tenant", "exists": False, "ids": {"tenant_id": "tx"}},
                {
                    "key": "PA1",
                    "kind": "project",
                    "tenant": "A",
                    "attributes": {"market": "UK"},
                    "ids": {"project_id": "pa1"},
                },
                {
                    "key": "PA2",
                    "kind": "project",
                    "tenant": "A",
                    "attributes": {"market": "US"},
                    "ids": {"project_id": "pa2"},
                },
                {
                    "key": "PB1",
                    "kind": "project",
                    "tenant": "B",
                    "attributes": {"market": "US"},
                    "ids": {"project_id": "pb1"},
                },
                {
                    "key": "PC1",
                    "kind": "project",
                    "tenant": "C",
                    "attributes": {"market": "UK"},
                    "ids": {"project_id": "pc1"},
                },
                {"key": "PX", "kind": "project", "exists": False, "ids": {"project_id": "px"}},
            ],
            "actions": [
                {
                    "id": "project.read",
                    "method": "GET",
                    "path": "/v1/projects/{project_id}",
                    "resource_kind": "project",
                    "surface": "project.detail",
                },
                {
                    "id": "project.list",
                    "method": "GET",
                    "path": "/v1/tenants/{tenant_id}/projects",
                    "resource_kind": "tenant",
                    "surface": "project.list_item",
                    "list": {
                        "kind": "project",
                        "id_key": "project_id",
                        "item_id_field": "id",
                        "total_field": "total",
                    },
                },
                {
                    "id": "contact.private.read",
                    "method": "GET",
                    "path": "/v1/projects/{project_id}/contacts",
                    "resource_kind": "project",
                    "surface": "contacts.private",
                    "page": True,
                },
            ],
            "policy": {
                "roles": ["viewer", "editor", "admin", "owner"],
                "hidden_is_not_found": True,
                "capabilities": {
                    "project.read": ["viewer", "editor", "admin", "owner"],
                    "project.list": ["viewer", "editor", "admin", "owner"],
                    "contact.private.read": ["admin", "owner"],
                },
                "fields": {
                    "project.detail": {
                        "id": "viewer",
                        "title": "viewer",
                        "contacts": "viewer",
                        "contacts[].id": "viewer",
                        "owner_principal_id": "editor",
                    },
                    "project.list_item": {"id": "viewer", "title": "viewer"},
                    "contacts.private": {"id": "viewer", "email_private": "admin"},
                },
                "concealment": {"ignore_body_fields": ["request_id"]},
            },
            "redaction": {"mask_fields": ["email_private"]},
        }
    )


def dump(data: dict[str, Any]) -> str:
    return yaml.safe_dump(data, sort_keys=False)


def parse(data: dict[str, Any]) -> Any:
    from boundarycheck.config import parse_config  # noqa: PLC0415

    return parse_config(dump(data))


# ----------------------------------------------------------------- a tiny hostile HTTP server ----
class FakeServer:
    """A real HTTP server on 127.0.0.1 for the live-transport tests. `routes` maps a path to a
    callable (handler) -> None, or to (status, headers, body). It records every request."""

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.routes: dict[str, Any] = {}
        self.default: Any = None  # a catch-all handler for paths without a route
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:  # silence
                return

            def do_GET(self) -> None:
                outer.requests.append({"method": "GET", "path": self.path, "headers": dict(self.headers)})
                route = outer.routes.get(self.path) or outer.default
                if route is None:
                    self._send(404, {"content-type": "application/json"}, b'{"code":"resource.not_found"}')
                elif callable(route):
                    route(self)
                else:
                    self._send(*route)

            do_HEAD = do_GET

            def _send(self, status: int, headers: dict[str, str], body: bytes) -> None:
                self.send_response(status)
                for name, value in headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                    self.wfile.write(body)

        self.send = Handler._send
        self.httpd = ThreadingHTTPServer((LOOPBACK, 0), Handler)
        self.port = self.httpd.server_address[1]
        self.base_url = f"http://{LOOPBACK}:{self.port}"
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def json(self, path: str, payload: Any, status: int = 200) -> None:
        self.routes[path] = (
            status,
            {"content-type": "application/json"},
            json.dumps(payload).encode(),
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


@contextmanager
def fake_server() -> Iterator[FakeServer]:
    server = FakeServer()
    server.start()
    try:
        yield server
    finally:
        server.stop()


def slow(seconds: float) -> Callable[[Any], None]:
    def handler(h: Any) -> None:
        time.sleep(seconds)
        h._send(200, {"content-type": "application/json"}, b"{}")

    return handler


def gzip_bomb(decoded_bytes: int) -> Callable[[Any], None]:
    payload = gzip.compress(b"0" * decoded_bytes)

    def handler(h: Any) -> None:
        h._send(200, {"content-type": "application/json", "content-encoding": "gzip"}, payload)

    return handler


# ------------------------------------------------------------------ an in-memory fake target ----
class FakeTransport:
    """A transport whose answers come from a function. It records everything it was asked."""

    name = "fake"

    def __init__(
        self,
        responder: Callable[[str, str, str | None], Any],
        creds: set[str] | None = None,
        secrets: list[str] | None = None,
    ) -> None:
        self.responder = responder
        self.creds = creds
        self._secrets = secrets or []
        self.sent: list[tuple[str, str, str | None]] = []
        self.closed = False

    def has_credential(self, principal: str | None) -> bool:
        return principal is None or self.creds is None or principal in self.creds

    def secrets(self) -> list[str]:
        return list(self._secrets)

    async def send(self, method: str, path: str, principal: str | None) -> Any:
        self.sent.append((method, path, principal))
        result = self.responder(method, path, principal)
        if isinstance(result, Exception):
            raise result
        return result

    async def aclose(self) -> None:
        self.closed = True


def compliant(config: Any, *, tweak: Callable[[Any, Any], Any] | None = None) -> Callable[[str, str, str | None], Any]:
    """A target that behaves exactly as the declared policy says (built with the product's own
    oracle: fine for testing the engine's plumbing, never for judging a target). `tweak(case,
    observation)` may return a different observation for chosen cases."""
    from boundarycheck.model import Observation, Outcome  # noqa: PLC0415
    from boundarycheck.planner import plan  # noqa: PLC0415

    by_request = {(c.principal, c.path): c for c in plan(config)}
    status = {
        Outcome.ALLOW: 200,
        Outcome.DENY_UNAUTHENTICATED: 401,
        Outcome.DENY_FORBIDDEN: 403,
        Outcome.DENY_NOT_FOUND: 404,
    }
    counter = {"n": 0}

    def respond(method: str, path: str, principal: str | None) -> Any:
        case = by_request[(principal, path)]
        counter["n"] += 1
        exp = case.expected
        headers = {"content-type": "application/json", "x-request-id": f"req-{counter['n']}"}
        if exp.outcome is Outcome.ALLOW:
            if case.action.list_spec is not None:
                ids = sorted(exp.visible_ids or [])
                body: Any = {
                    "items": [{"id": i, "title": "t"} for i in ids],
                    "next_cursor": None,
                    "total": len(ids),
                }
            elif case.action.page:
                body = {"items": [], "next_cursor": None, "total": 0}
            else:
                body = {f: "x" for f in sorted(exp.visible_fields or []) if "[" not in f and "." not in f}
        else:
            body = {"code": exp.outcome.value, "request_id": f"req-{counter['n']}"}
        obs = Observation(status=status[exp.outcome], headers=headers, body=json.dumps(body).encode())
        return tweak(case, obs) if tweak else obs

    return respond
