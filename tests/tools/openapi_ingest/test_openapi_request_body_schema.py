"""Tests for the `request_body_schema` extraction added to
`openapi_spec_ingest._extract_endpoints`.

Schema extraction is what the schema-aware mass-assignment probe
consumes. Tests cover:
  * OpenAPI 3.x `requestBody.content.application/json.schema`
  * Swagger 2.x `parameters[in=body].schema`
  * `$ref` resolution against `#/components/schemas/X` (3.x) and
    `#/definitions/X` (2.x)
  * `readOnly` flag preservation
  * `required` field list preservation
  * Edge cases: missing requestBody, non-JSON content type,
    array schemas, inline (non-$ref) schemas
"""

from __future__ import annotations

from typing import Any

import pytest

from strix.tools.openapi_ingest.openapi_spec_ingest import (
    _extract_endpoints,
    _extract_request_body_schema,
    _resolve_ref,
)


# ---------------------------------------------------------------------------
# _resolve_ref unit tests
# ---------------------------------------------------------------------------


def test_resolve_ref_openapi_3_components() -> None:
    spec = {"components": {"schemas": {"User": {"type": "object"}}}}
    assert _resolve_ref("#/components/schemas/User", spec) == {"type": "object"}


def test_resolve_ref_swagger_2_definitions() -> None:
    spec = {"definitions": {"User": {"type": "object"}}}
    assert _resolve_ref("#/definitions/User", spec) == {"type": "object"}


def test_resolve_ref_unknown_path_returns_none() -> None:
    spec = {"components": {"schemas": {}}}
    assert _resolve_ref("#/components/schemas/NonExistent", spec) is None


def test_resolve_ref_invalid_format_returns_none() -> None:
    assert _resolve_ref("not a ref", {}) is None
    assert _resolve_ref("http://example.com", {}) is None
    assert _resolve_ref("", {}) is None


# ---------------------------------------------------------------------------
# _extract_request_body_schema — OpenAPI 3.x
# ---------------------------------------------------------------------------


def test_openapi3_inline_schema() -> None:
    """Inline schema in requestBody.content — no $ref."""
    operation = {
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "is_admin": {"type": "boolean", "readOnly": True},
                        },
                        "required": ["name"],
                    }
                }
            }
        }
    }
    out = _extract_request_body_schema(operation, spec={})
    assert out is not None
    assert out["source"] == "openapi3"
    assert "name" in out["properties"]
    assert "is_admin" in out["properties"]
    assert out["properties"]["is_admin"]["read_only"] is True
    assert out["properties"]["name"]["read_only"] is False
    assert out["required"] == ["name"]


def test_openapi3_ref_resolution() -> None:
    """Schema is a `$ref` to `#/components/schemas/X` — resolver
    walks one level and pulls the referenced object."""
    spec = {
        "components": {
            "schemas": {
                "Payment": {
                    "type": "object",
                    "properties": {
                        "amount": {"type": "number"},
                        "id": {"type": "string", "readOnly": True},
                    },
                }
            }
        }
    }
    operation = {
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {"$ref": "#/components/schemas/Payment"}
                }
            }
        }
    }
    out = _extract_request_body_schema(operation, spec=spec)
    assert out is not None
    assert out["source"] == "openapi3"
    assert "amount" in out["properties"]
    assert out["properties"]["id"]["read_only"] is True


def test_openapi3_property_level_ref_resolution() -> None:
    """One property is itself a `$ref` to another schema. The
    resolver resolves at the property level so readOnly + type
    flow through."""
    spec = {
        "components": {
            "schemas": {
                "User": {
                    "type": "object",
                    "properties": {
                        "addr": {"$ref": "#/components/schemas/Address"},
                    },
                },
                "Address": {
                    "type": "object",
                    "readOnly": True,
                },
            }
        }
    }
    operation = {
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {"$ref": "#/components/schemas/User"}
                }
            }
        }
    }
    out = _extract_request_body_schema(operation, spec=spec)
    assert out is not None
    # The Address property is resolved → its readOnly flag flows
    # through to the User.addr property.
    assert out["properties"]["addr"]["read_only"] is True


def test_openapi3_content_with_charset() -> None:
    """`application/json; charset=utf-8` is a valid JSON media type
    — must also be accepted."""
    operation = {
        "requestBody": {
            "content": {
                "application/json; charset=utf-8": {
                    "schema": {
                        "type": "object",
                        "properties": {"x": {"type": "string"}},
                    }
                }
            }
        }
    }
    out = _extract_request_body_schema(operation, spec={})
    assert out is not None
    assert "x" in out["properties"]


def test_openapi3_vnd_api_json_accepted() -> None:
    """JSON:API media type variant."""
    operation = {
        "requestBody": {
            "content": {
                "application/vnd.api+json": {
                    "schema": {
                        "type": "object",
                        "properties": {"data": {"type": "object"}},
                    }
                }
            }
        }
    }
    out = _extract_request_body_schema(operation, spec={})
    assert out is not None


def test_openapi3_no_json_content_returns_none() -> None:
    """Operation declares only `multipart/form-data` or
    `application/xml` — no JSON body to introspect."""
    operation = {
        "requestBody": {
            "content": {
                "application/xml": {
                    "schema": {"type": "object"},
                }
            }
        }
    }
    out = _extract_request_body_schema(operation, spec={})
    assert out is None


# ---------------------------------------------------------------------------
# _extract_request_body_schema — Swagger 2.x
# ---------------------------------------------------------------------------


def test_swagger2_inline_body_schema() -> None:
    operation = {
        "parameters": [
            {
                "name": "user",
                "in": "body",
                "required": True,
                "schema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "id": {"type": "integer", "readOnly": True},
                    },
                },
            }
        ]
    }
    out = _extract_request_body_schema(operation, spec={})
    assert out is not None
    assert out["source"] == "swagger2"
    assert "name" in out["properties"]
    assert out["properties"]["id"]["read_only"] is True


def test_swagger2_ref_resolution() -> None:
    spec = {
        "definitions": {
            "User": {
                "type": "object",
                "properties": {"id": {"type": "string", "readOnly": True}},
            }
        }
    }
    operation = {
        "parameters": [
            {
                "name": "user", "in": "body",
                "schema": {"$ref": "#/definitions/User"},
            }
        ]
    }
    out = _extract_request_body_schema(operation, spec=spec)
    assert out is not None
    assert out["source"] == "swagger2"
    assert out["properties"]["id"]["read_only"] is True


# ---------------------------------------------------------------------------
# _extract_request_body_schema — degenerate / edge cases
# ---------------------------------------------------------------------------


def test_no_request_body_returns_none() -> None:
    """Operation without a requestBody (e.g. GET) returns None."""
    assert _extract_request_body_schema({}, spec={}) is None


def test_empty_properties_returns_none() -> None:
    """Schema with no `properties` key (e.g. allOf composition,
    array schemas) — return None so the consumer falls back to
    canonical fields."""
    operation = {
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {"type": "object"},  # no properties
                }
            }
        }
    }
    assert _extract_request_body_schema(operation, spec={}) is None


def test_array_schema_returns_none() -> None:
    operation = {
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                }
            }
        }
    }
    assert _extract_request_body_schema(operation, spec={}) is None


def test_broken_ref_returns_none() -> None:
    operation = {
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {"$ref": "#/components/schemas/Missing"}
                }
            }
        }
    }
    # Spec doesn't define `Missing` → resolver returns None →
    # extractor returns None.
    assert _extract_request_body_schema(operation, spec={"components": {"schemas": {}}}) is None


# ---------------------------------------------------------------------------
# End-to-end: _extract_endpoints carries request_body_schema
# ---------------------------------------------------------------------------


def test_endpoints_carry_request_body_schema_for_write_methods() -> None:
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/users": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/User"}
                            }
                        }
                    },
                    "responses": {"200": {"description": "OK"}},
                }
            }
        },
        "components": {
            "schemas": {
                "User": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "id": {"type": "integer", "readOnly": True},
                    },
                }
            }
        },
    }
    endpoints = _extract_endpoints(spec, base_url="https://api.example.com")
    assert len(endpoints) == 1
    ep = endpoints[0]
    assert ep["method"] == "POST"
    assert ep["request_body_schema"] is not None
    assert "name" in ep["request_body_schema"]["properties"]
    assert ep["request_body_schema"]["properties"]["id"]["read_only"] is True


def test_endpoints_no_request_body_schema_for_read_methods() -> None:
    """GET / HEAD / DELETE / OPTIONS don't have semantic request
    bodies; the extractor skips them to keep output clean."""
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/users/{id}": {
                "get": {
                    "responses": {"200": {"description": "OK"}},
                },
                "delete": {
                    "responses": {"204": {"description": "OK"}},
                },
            }
        },
    }
    endpoints = _extract_endpoints(spec, base_url="https://api.example.com")
    assert len(endpoints) == 2
    for ep in endpoints:
        assert ep["request_body_schema"] is None
