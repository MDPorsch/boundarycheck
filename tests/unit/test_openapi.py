"""v0.3 (docs/design-v0.3.md s5): OpenAPI import writes a SKELETON config. The spec is untrusted input, only
local $refs are followed, nothing is fetched, nothing the spec says can inject YAML, and the placeholders fail
loud (nobody may do anything; every field needs the highest role) until a person writes the policy."""

from __future__ import annotations

import copy
import json
import socket
from typing import Any

import pytest
import yaml

from tests.support import parse

pytestmark = pytest.mark.milestone("V3")


def spec() -> dict[str, Any]:
    return copy.deepcopy(
        {
            "openapi": "3.0.3",
            "info": {"title": "Acme API", "version": "1.2.3"},
            "servers": [{"url": "https://api.acme.example/v1"}],
            "components": {
                "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}},
                "schemas": {
                    "Contact": {
                        "type": "object",
                        "properties": {"id": {"type": "string"}, "publicName": {"type": "string"}},
                    },
                    "Project": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"},
                            "title": {"type": "string"},
                            "tenantId": {"type": "string"},
                            "contacts": {"type": "array", "items": {"$ref": "#/components/schemas/Contact"}},
                        },
                    },
                    "ProjectList": {
                        "type": "object",
                        "properties": {
                            "items": {"type": "array", "items": {"$ref": "#/components/schemas/Project"}},
                            "total": {"type": "integer"},
                            "next_cursor": {"type": "string"},
                        },
                    },
                    "Invoice": {
                        "type": "object",
                        "properties": {"id": {"type": "string"}, "amountMinor": {"type": "integer"}},
                    },
                },
            },
            "security": [{"bearerAuth": []}],
            "paths": {
                "/": {
                    "get": {
                        "operationId": "rootInfo",
                        "responses": {
                            "200": {
                                "content": {
                                    "application/json": {
                                        "schema": {"type": "object", "properties": {"version": {"type": "string"}}}
                                    }
                                }
                            }
                        },
                    }
                },
                "/v1/me": {
                    "get": {
                        "operationId": "whoAmI",
                        "responses": {
                            "200": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {"id": {"type": "string"}, "email": {"type": "string"}},
                                        }
                                    }
                                }
                            }
                        },
                    }
                },
                "/v1/tenants/{tenantId}/projects": {
                    "get": {
                        "operationId": "listProjects",
                        "responses": {
                            "200": {
                                "content": {
                                    "application/json": {"schema": {"$ref": "#/components/schemas/ProjectList"}}
                                }
                            }
                        },
                    },
                    "post": {"operationId": "createProject", "responses": {"201": {}}},
                },
                "/v1/projects/{projectId}": {
                    "parameters": [{"name": "projectId", "in": "path", "required": True, "schema": {"type": "string"}}],
                    "get": {
                        "operationId": "getProject",
                        "responses": {
                            "200": {
                                "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Project"}}}
                            }
                        },
                    },
                    "patch": {"operationId": "updateProject", "responses": {"200": {}}},
                    "delete": {"operationId": "deleteProject", "responses": {"204": {}}},
                },
                "/v1/projects/{projectId}/invoices/{invoiceId}": {
                    "get": {
                        "operationId": "getInvoice",
                        "responses": {
                            "200": {
                                "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Invoice"}}}
                            }
                        },
                    }
                },
            },
        }
    )


def _import(document: Any, as_yaml: bool = False) -> Any:
    from boundarycheck.openapi import import_openapi  # noqa: PLC0415

    raw = yaml.safe_dump(document, sort_keys=False) if as_yaml else json.dumps(document)
    return import_openapi(raw)


def _doc(result: Any) -> dict[str, Any]:
    loaded: dict[str, Any] = yaml.safe_load(result.yaml_text)
    return loaded


def _actions(result: Any) -> dict[str, dict[str, Any]]:
    return {a["id"]: a for a in _doc(result)["actions"]}


# -------------------------------------------------------------------------------- the skeleton ----
def test_the_skeleton_validates_with_the_real_config_loader_and_plans_requests() -> None:
    from boundarycheck.config import parse_config  # noqa: PLC0415
    from boundarycheck.planner import plan  # noqa: PLC0415

    result = _import(spec())
    cfg = parse_config(result.yaml_text)
    assert plan(cfg)


def test_only_get_and_head_operations_become_actions_and_the_rest_are_counted() -> None:
    result = _import(spec())
    assert set(_actions(result)) == {"rootInfo", "whoAmI", "listProjects", "getProject", "getInvoice"}
    assert all(a["method"] in {"GET", "HEAD"} for a in _actions(result).values())
    assert result.skipped == 3 and any("createProject" in n or "write" in n.lower() for n in result.notes)


def test_paths_use_snake_case_parameters_and_resources_carry_every_id_an_action_needs() -> None:
    result = _import(spec())
    actions, doc = _actions(result), _doc(result)
    assert (
        actions["listProjects"]["path"] == "/v1/tenants/{tenant_id}/projects"
        and actions["listProjects"]["resource_kind"] == "tenant"
    )
    assert (
        actions["getProject"]["path"] == "/v1/projects/{project_id}"
        and actions["getProject"]["resource_kind"] == "project"
    )
    assert (
        actions["getInvoice"]["path"] == "/v1/projects/{project_id}/invoices/{invoice_id}"
        and actions["getInvoice"]["resource_kind"] == "invoice"
    )
    assert actions["whoAmI"]["resource_kind"] == "root" and actions["rootInfo"]["path"] == "/"
    invoice_resources = [r for r in doc["resources"] if r["kind"] == "invoice"]
    assert invoice_resources and all({"project_id", "invoice_id"} <= set(r["ids"]) for r in invoice_resources)


def test_every_kind_gets_two_real_looking_placeholders_and_one_that_does_not_exist() -> None:
    doc = _doc(_import(spec()))
    for kind in ("tenant", "project", "invoice"):
        mine = [r for r in doc["resources"] if r["kind"] == kind]
        assert len(mine) == 3 and sum(1 for r in mine if r.get("exists") is False) == 1
        assert all("REPLACE" in v for r in mine for v in r["ids"].values())


def test_a_list_response_with_items_is_a_paged_action_with_item_field_paths() -> None:
    result = _import(spec())
    action = _actions(result)["listProjects"]
    fields = _doc(result)["policy"]["fields"][action["surface"]]
    assert action.get("page") is True
    assert {
        "items[].id",
        "items[].title",
        "items[].tenantId",
        "items[].contacts",
        "items[].contacts[].publicName",
    } <= set(fields)


def test_field_paths_keep_the_names_the_api_returns_not_snake_case() -> None:
    result = _import(spec())
    fields = _doc(result)["policy"]["fields"][_actions(result)["getProject"]["surface"]]
    assert {"id", "title", "tenantId", "contacts", "contacts[].id", "contacts[].publicName"} <= set(fields)


def test_the_placeholders_fail_loud_nobody_may_do_anything_and_every_field_needs_the_top_role() -> None:
    doc = _doc(_import(spec()))
    assert doc["policy"]["roles"] == ["viewer", "editor", "admin", "owner"]
    assert doc["policy"]["capabilities"] and all(v == [] for v in doc["policy"]["capabilities"].values())
    assert all(role == "owner" for fields in doc["policy"]["fields"].values() for role in fields.values())


def test_the_skeleton_says_it_is_a_skeleton_and_what_to_edit() -> None:
    text = _import(spec()).yaml_text
    head = "\n".join(line for line in text.splitlines() if line.startswith("#")).lower()
    assert "skeleton" in head and "edit" in head and "policy" in head and "capabilities" in head


def test_servers_appear_only_in_a_comment_and_no_remote_base_url_is_written() -> None:
    result = _import(spec())
    doc = _doc(result)
    assert doc["scope"]["target"]["base_url"].startswith("http://127.0.0.1")
    assert "allowed_hosts" not in doc["scope"]["target"] and "authorization" not in doc["scope"]
    assert any(line.startswith("#") and "api.acme.example" in line for line in result.yaml_text.splitlines())
    assert "api.acme.example" not in yaml.safe_dump(doc)


def test_yaml_input_works_like_json_input() -> None:
    assert _import(spec(), as_yaml=True).yaml_text == _import(spec()).yaml_text


def test_the_output_is_deterministic() -> None:
    assert _import(spec()).yaml_text == _import(spec()).yaml_text


# ---------------------------------------------------------------------------- credentials ----
def _with_scheme(scheme: dict[str, Any]) -> dict[str, Any]:
    document = spec()
    document["components"]["securitySchemes"] = {"s": scheme}
    document["security"] = [{"s": []}]
    return document


@pytest.mark.parametrize(
    ("scheme", "expected"),
    [
        ({"type": "http", "scheme": "bearer"}, ("bearer", None)),
        ({"type": "oauth2", "flows": {}}, ("bearer", None)),
        ({"type": "apiKey", "in": "header", "name": "X-API-Key"}, ("header", "X-API-Key")),
        ({"type": "apiKey", "in": "cookie", "name": "session"}, ("cookie", "session")),
    ],
)
def test_the_security_scheme_chooses_the_credential_scheme_of_the_principals(
    scheme: dict[str, Any], expected: tuple[str, str | None]
) -> None:
    for principal in _doc(_import(_with_scheme(scheme)))["principals"].values():
        cred = principal["credential"]
        assert (cred.get("in", "bearer"), cred.get("name")) == expected
        assert "env" in cred and "keychain" not in cred


@pytest.mark.parametrize(
    "scheme",
    [
        {"type": "apiKey", "in": "query", "name": "key"},
        {"type": "http", "scheme": "basic"},
        {"type": "apiKey", "in": "header", "name": "Host"},
    ],
)
def test_an_unsupported_scheme_is_a_note_and_a_bearer_default(scheme: dict[str, Any]) -> None:
    result = _import(_with_scheme(scheme))
    assert any("not supported" in n.lower() or "unsupported" in n.lower() for n in result.notes)
    assert all("in" not in p["credential"] for p in _doc(result)["principals"].values())


# --------------------------------------------------------------------------------- hostile ----
def test_an_external_ref_is_refused_and_nothing_is_fetched(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_network(*_a: Any, **_k: Any) -> None:
        raise AssertionError("the importer must never open a socket")

    monkeypatch.setattr(socket, "socket", no_network)
    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    document = spec()
    document["paths"]["/v1/me"]["get"]["responses"]["200"]["content"]["application/json"]["schema"] = {
        "$ref": "https://evil.example/x.json#/Foo"
    }
    document["paths"]["/v1/projects/{projectId}"]["get"]["responses"]["200"]["content"]["application/json"][
        "schema"
    ] = {"$ref": "other.yaml#/Foo"}
    document["paths"]["/"]["get"]["responses"]["200"]["content"]["application/json"]["schema"] = {
        "$ref": "file:///etc/passwd"
    }
    result = _import(document)
    assert sum("external" in n.lower() or "local" in n.lower() for n in result.notes) >= 3


def test_a_cyclic_ref_terminates() -> None:
    document = spec()
    document["components"]["schemas"]["Node"] = {
        "type": "object",
        "properties": {
            "id": {"type": "string"},
            "children": {"type": "array", "items": {"$ref": "#/components/schemas/Node"}},
            "parent": {"$ref": "#/components/schemas/Node"},
        },
    }
    document["paths"]["/v1/me"]["get"]["responses"]["200"]["content"]["application/json"]["schema"] = {
        "$ref": "#/components/schemas/Node"
    }
    fields = _doc(_import(document))["policy"]["fields"]
    assert any("children" in key for fs in fields.values() for key in fs)


def test_a_ref_that_points_nowhere_is_a_note_not_a_crash() -> None:
    document = spec()
    document["paths"]["/v1/me"]["get"]["responses"]["200"]["content"]["application/json"]["schema"] = {
        "$ref": "#/components/schemas/Missing"
    }
    result = _import(document)
    assert "whoAmI" in _actions(result) and any("whoAmI" in n or "Missing" in n for n in result.notes)


def test_an_oversized_spec_is_refused_before_it_is_parsed() -> None:
    from boundarycheck.openapi import MAX_SPEC_BYTES, OpenApiError, import_openapi  # noqa: PLC0415

    with pytest.raises(OpenApiError, match="too large"):
        import_openapi("a" * (MAX_SPEC_BYTES + 1))


def test_yaml_aliases_and_anchors_are_refused() -> None:
    from boundarycheck.openapi import OpenApiError, import_openapi  # noqa: PLC0415

    with pytest.raises(OpenApiError, match=r"(?i)alias|anchor"):
        import_openapi("openapi: 3.0.3\nx: &a [1]\ny: *a\npaths: {}\n")


def test_a_deeply_nested_document_is_refused_not_a_stack_overflow() -> None:
    from boundarycheck.openapi import OpenApiError, import_openapi  # noqa: PLC0415

    with pytest.raises(OpenApiError):
        import_openapi("openapi: 3.0.3\npaths: {}\nx: " + "[" * 5000 + "]" * 5000)
    nested: dict[str, Any] = {}
    node = nested
    for _ in range(3000):
        node["a"] = {}
        node = node["a"]
    with pytest.raises(OpenApiError):
        import_openapi(json.dumps({"openapi": "3.0.3", "paths": {}, "x": nested}))


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "[]",
        "42",
        "{",
        "openapi: 3.0.3",
        "swagger: '2.0'\npaths: {}",
        "openapi: 2.9\npaths: {}",
        "openapi: 3.0.3\npaths: []",
        "\x00\x01\x02",
    ],
)
def test_a_document_that_is_not_openapi_3_is_refused_with_a_clear_message(raw: str) -> None:
    from boundarycheck.openapi import OpenApiError, import_openapi  # noqa: PLC0415

    with pytest.raises(OpenApiError):
        import_openapi(raw)


@pytest.mark.parametrize(
    "path",
    [
        "/v1/a:b",
        "/v1/a%2eb",
        "/v1/../x",
        "/v1/./x",
        "/v1//x",
        "/v1/x y",
        "/v1/é",
        "/v1/{id}.json",
        "/v1/pre{id}",
        "no-leading-slash",
        "/v1/x?y=1",
        "/v1/x#f",
        "/v1/{a b}",
        "/v1/{}",
        "/" + "a" * 300,
    ],
)
def test_a_path_the_config_could_not_hold_is_skipped_with_a_note_never_passed_through(path: str) -> None:
    document = spec()
    document["paths"][path] = {"get": {"operationId": "odd", "responses": {"200": {}}}}
    result = _import(document)
    assert "odd" not in _actions(result) and any("skipped" in n.lower() for n in result.notes)


def test_names_that_do_not_fit_the_alphabets_are_skipped_so_nothing_can_inject_yaml() -> None:
    document = spec()
    document["components"]["schemas"]["Project"]["properties"]["evil\n- id: injected"] = {"type": "string"}
    document["components"]["schemas"]["Project"]["properties"]["a: b"] = {"type": "string"}
    document["components"]["schemas"]["Project"]["properties"]["# x"] = {"type": "string"}
    document["paths"]["/v1/me"]["get"]["operationId"] = "evil\nactions: []"
    result = _import(document)
    doc = _doc(result)
    assert not any("injected" in key or "a: b" in key for fs in doc["policy"]["fields"].values() for key in fs)
    assert all("\n" not in a["id"] for a in doc["actions"]) and "evil" not in "".join(a["id"] for a in doc["actions"])
    assert [a["id"] for a in doc["actions"]].count("injected") == 0


def test_the_title_and_servers_in_the_header_comment_cannot_break_out_of_the_comment() -> None:
    document = spec()
    document["info"]["title"] = "Evil\nactions: []\nprincipals: {}\n# end"
    document["servers"] = [{"url": "https://x.example/\nbase_url: http://evil"}]
    result = _import(document)
    top = [
        line
        for line in result.yaml_text.splitlines()
        if not line.startswith(" ") and ":" in line and not line.startswith("#") and not line.startswith("-")
    ]
    assert top.count("actions:") == 1 and top.count("principals:") == 1
    assert _doc(result)["scope"]["target"]["base_url"].startswith("http://127.0.0.1")
    assert all(
        line.startswith("#") or line == "" or not line.startswith("evil") for line in result.yaml_text.splitlines()
    )


def test_the_number_of_operations_is_capped() -> None:
    from boundarycheck.openapi import MAX_OPERATIONS  # noqa: PLC0415

    document = spec()
    for n in range(MAX_OPERATIONS + 50):
        document["paths"][f"/v1/bulk{n}"] = {"get": {"operationId": f"bulk{n}", "responses": {"200": {}}}}
    result = _import(document)
    assert len(_doc(result)["actions"]) <= MAX_OPERATIONS and any(
        "first" in n.lower() and str(MAX_OPERATIONS) in n for n in result.notes
    )


def test_duplicate_and_odd_operation_ids_become_unique_valid_ids() -> None:
    document = spec()
    document["paths"]["/v1/a"] = {"get": {"operationId": "dup", "responses": {"200": {}}}}
    document["paths"]["/v1/b"] = {"get": {"operationId": "dup", "responses": {"200": {}}}}
    document["paths"]["/v1/c"] = {"get": {"operationId": "has spaces!", "responses": {"200": {}}}}
    document["paths"]["/v1/d"] = {"get": {"responses": {"200": {}}}}
    result = _import(document)
    ids = [a["id"] for a in _doc(result)["actions"]]
    assert len(ids) == len(set(ids)) and {"dup"} <= set(ids)
    parse_cfg = parse  # the whole output still validates
    assert parse_cfg(yaml.safe_load(result.yaml_text)) is not None


def test_a_document_with_no_readable_operation_is_a_clear_error() -> None:
    from boundarycheck.openapi import OpenApiError, import_openapi  # noqa: PLC0415

    with pytest.raises(OpenApiError, match=r"(?i)no GET"):
        import_openapi(json.dumps({"openapi": "3.0.3", "paths": {"/x": {"post": {"responses": {"200": {}}}}}}))


def test_the_importer_never_writes_a_secret_or_a_token_placeholder_that_looks_like_one() -> None:
    text = _import(spec()).yaml_text
    assert "Bearer" not in text and "BC_TOKEN_" in text  # env NAMES only
    assert parse(yaml.safe_load(text)) is not None  # and the whole output validates


def test_a_document_nested_deeper_than_the_cap_is_refused_even_when_it_would_still_parse() -> None:
    from boundarycheck.openapi import MAX_DEPTH, OpenApiError, import_openapi  # noqa: PLC0415

    nested: dict[str, Any] = {}
    node = nested
    for _ in range(MAX_DEPTH + 5):
        node["a"] = {}
        node = node["a"]
    with pytest.raises(OpenApiError, match="deeply"):
        import_openapi(json.dumps({**spec(), "x-deep": nested}))
