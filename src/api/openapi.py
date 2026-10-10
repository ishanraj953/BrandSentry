#!/usr/bin/env python3
"""OpenAPI 3.0 description of the BrandSentra REST API."""

from __future__ import annotations

from typing import Any, Dict

from src import __version__

_SEVERITY = {"type": "string", "enum": ["critical", "high", "medium", "low"]}
_STATUS = {"type": "string", "enum": ["open", "investigating", "resolved", "false_positive"]}


def _param(
    name: str, where: str, schema: Dict[str, Any], description: str = "", required: bool = False
):
    return {
        "name": name,
        "in": where,
        "required": required,
        "schema": schema,
        "description": description,
    }


def _json_body(schema_ref: str, required: bool = True) -> Dict[str, Any]:
    return {"required": required, "content": {"application/json": {"schema": {"$ref": schema_ref}}}}


def _resp(
    description: str, schema: Any = None, content_type: str = "application/json"
) -> Dict[str, Any]:
    out: Dict[str, Any] = {"description": description}
    if schema is not None:
        out["content"] = {content_type: {"schema": schema}}
    return out


ERROR = _resp("Error", {"$ref": "#/components/schemas/Error"})


def build_spec(base_url: str = "/") -> Dict[str, Any]:
    """Return the OpenAPI document as a plain dict."""
    limit = _param("limit", "query", {"type": "integer", "default": 50, "maximum": 500})
    offset = _param("offset", "query", {"type": "integer", "default": 0})
    domain_path = _param("domain", "path", {"type": "string"}, "Hostname or URL", True)
    secured = [{"bearerAuth": []}, {"apiKeyAuth": []}]

    paths: Dict[str, Any] = {
        "/api/v1/health": {
            "get": {
                "tags": ["system"],
                "summary": "Health check",
                "responses": {"200": _resp("OK")},
            }
        },
        "/api/v1/auth/login": {
            "post": {
                "tags": ["auth"],
                "summary": "Obtain a signed bearer token",
                "requestBody": _json_body("#/components/schemas/LoginRequest"),
                "responses": {
                    "200": _resp("Token", {"$ref": "#/components/schemas/LoginResponse"}),
                    "401": ERROR,
                },
            }
        },
        "/api/v1/auth/me": {
            "get": {
                "tags": ["auth"],
                "summary": "Current principal",
                "security": secured,
                "responses": {"200": _resp("Principal"), "401": ERROR},
            }
        },
        "/api/v1/scan/domain": {
            "post": {
                "tags": ["scan"],
                "summary": "Analyse one hostname (phishing heuristics, squatting, brand alerts)",
                "requestBody": _json_body("#/components/schemas/ScanRequest"),
                "responses": {
                    "200": _resp("Scan result", {"$ref": "#/components/schemas/ScanResult"}),
                    "400": ERROR,
                },
            }
        },
        "/api/v1/scan/bulk": {
            "post": {
                "tags": ["scan"],
                "summary": "Analyse up to N hostnames",
                "requestBody": _json_body("#/components/schemas/BulkScanRequest"),
                "responses": {"200": _resp("Bulk results"), "400": ERROR},
            }
        },
        "/api/v1/scans/history": {
            "get": {
                "tags": ["scan"],
                "summary": "Recent scans",
                "parameters": [limit, _param("domain", "query", {"type": "string"})],
                "responses": {"200": _resp("Scans")},
            }
        },
        "/api/v1/brands": {
            "get": {
                "tags": ["brands"],
                "summary": "Monitored brand profiles",
                "responses": {"200": _resp("Brands")},
            }
        },
        "/api/v1/brands/permutations": {
            "post": {
                "tags": ["brands"],
                "summary": "Generate squatting permutations for a brand domain",
                "requestBody": _json_body("#/components/schemas/PermutationRequest"),
                "responses": {"200": _resp("Permutations"), "400": ERROR},
            }
        },
        "/api/v1/alerts": {
            "get": {
                "tags": ["alerts"],
                "summary": "List alerts",
                "parameters": [
                    _param("status", "query", {"type": "string"}, "Comma separated statuses"),
                    _param("severity", "query", {"type": "string"}, "Comma separated severities"),
                    _param("brand", "query", {"type": "string"}),
                    _param("domain", "query", {"type": "string"}),
                    _param("type", "query", {"type": "string"}),
                    _param("since", "query", {"type": "string", "format": "date-time"}),
                    _param("open_only", "query", {"type": "boolean"}),
                    limit,
                    offset,
                ],
                "responses": {"200": _resp("Alerts", {"$ref": "#/components/schemas/AlertList"})},
            }
        },
        "/api/v1/alerts/export": {
            "get": {
                "tags": ["alerts"],
                "summary": "Export alerts as CSV, JSON or STIX 2.1",
                "parameters": [
                    _param(
                        "format",
                        "query",
                        {"type": "string", "enum": ["csv", "json", "stix"], "default": "json"},
                    ),
                    _param("status", "query", {"type": "string"}),
                    _param("severity", "query", {"type": "string"}),
                    _param("since", "query", {"type": "string"}),
                    limit,
                ],
                "responses": {"200": _resp("Export")},
            }
        },
        "/api/v1/alerts/{alert_id}": {
            "parameters": [_param("alert_id", "path", {"type": "string"}, required=True)],
            "get": {
                "tags": ["alerts"],
                "summary": "Alert detail with history",
                "responses": {"200": _resp("Alert"), "404": ERROR},
            },
            "patch": {
                "tags": ["alerts"],
                "summary": "Update alert status / assignee / notes",
                "security": secured,
                "requestBody": _json_body("#/components/schemas/AlertUpdate"),
                "responses": {"200": _resp("Alert"), "400": ERROR, "401": ERROR, "404": ERROR},
            },
        },
        "/api/v1/allowlist": {
            "get": {
                "tags": ["allowlist"],
                "summary": "Allowlisted domains",
                "responses": {"200": _resp("Allowlist")},
            },
            "post": {
                "tags": ["allowlist"],
                "summary": "Allowlist a domain (and its subdomains)",
                "security": secured,
                "requestBody": _json_body("#/components/schemas/AllowlistRequest"),
                "responses": {
                    "201": _resp("Created"),
                    "200": _resp("Already present"),
                    "401": ERROR,
                },
            },
        },
        "/api/v1/allowlist/{domain}": {
            "parameters": [domain_path],
            "delete": {
                "tags": ["allowlist"],
                "summary": "Remove an allowlist entry",
                "security": secured,
                "responses": {"200": _resp("Removed"), "404": ERROR},
            },
        },
        "/api/v1/intel/{domain}": {
            "parameters": [domain_path, _param("refresh", "query", {"type": "boolean"})],
            "get": {
                "tags": ["intel"],
                "summary": "Threat-intelligence lookup (VirusTotal, URLhaus, OpenPhish ...)",
                "responses": {"200": _resp("Intel result")},
            },
        },
        "/api/v1/enrich/{domain}": {
            "parameters": [
                domain_path,
                _param("dns", "query", {"type": "boolean", "default": True}),
                _param("rdap", "query", {"type": "boolean", "default": True}),
                _param("tls", "query", {"type": "boolean", "default": False}),
                _param("whois", "query", {"type": "boolean", "default": False}),
            ],
            "get": {
                "tags": ["intel"],
                "summary": "DNS / RDAP / TLS enrichment",
                "responses": {"200": _resp("Enrichment")},
            },
        },
        "/api/v1/squats/sightings": {
            "get": {
                "tags": ["squats"],
                "summary": "Live typosquat sightings",
                "parameters": [
                    _param("brand", "query", {"type": "string"}),
                    _param("status", "query", {"type": "string"}),
                    limit,
                    offset,
                ],
                "responses": {"200": _resp("Sightings")},
            }
        },
        "/api/v1/squats/sightings/{domain}": {
            "parameters": [domain_path],
            "patch": {
                "tags": ["squats"],
                "summary": "Triage a sighting",
                "security": secured,
                "requestBody": _json_body("#/components/schemas/SightingUpdate"),
                "responses": {"200": _resp("Sighting"), "404": ERROR},
            },
        },
        "/api/v1/squats/check": {
            "post": {
                "tags": ["squats"],
                "summary": "Resolve permutations of a brand now",
                "security": secured,
                "requestBody": _json_body("#/components/schemas/SquatCheckRequest"),
                "responses": {"200": _resp("Run summary")},
            }
        },
        "/api/v1/stats": {
            "get": {
                "tags": ["system"],
                "summary": "Dashboard statistics",
                "responses": {"200": _resp("Stats")},
            }
        },
        "/api/v1/reports/summary": {
            "get": {
                "tags": ["reports"],
                "summary": "Summary report",
                "parameters": [
                    _param("days", "query", {"type": "integer", "default": 7}),
                    _param("format", "query", {"type": "string", "enum": ["json", "markdown"]}),
                ],
                "responses": {"200": _resp("Report")},
            }
        },
        "/api/v1/export/stix": {
            "get": {
                "tags": ["reports"],
                "summary": "STIX 2.1 bundle of indicators",
                "parameters": [
                    _param("min_risk", "query", {"type": "number", "default": 40}),
                    _param(
                        "tlp",
                        "query",
                        {"type": "string", "enum": ["white", "green", "amber", "red"]},
                    ),
                    limit,
                ],
                "responses": {"200": _resp("Bundle")},
            }
        },
        "/api/v1/certstream/status": {
            "get": {
                "tags": ["system"],
                "summary": "CertStream monitor heartbeat",
                "responses": {"200": _resp("Status")},
            }
        },
        "/api/v1/certstream/events": {
            "get": {
                "tags": ["system"],
                "summary": "Recent matched certificates",
                "parameters": [limit],
                "responses": {"200": _resp("Events")},
            }
        },
        "/api/v1/config": {
            "get": {
                "tags": ["system"],
                "summary": "Effective configuration (secrets masked)",
                "security": secured,
                "responses": {"200": _resp("Config"), "403": ERROR},
            }
        },
        "/metrics": {
            "get": {
                "tags": ["system"],
                "summary": "Prometheus metrics",
                "responses": {"200": _resp("Metrics", {"type": "string"}, "text/plain")},
            }
        },
    }

    schemas: Dict[str, Any] = {
        "Error": {
            "type": "object",
            "properties": {"error": {"type": "string"}, "code": {"type": "integer"}},
        },
        "LoginRequest": {
            "type": "object",
            "required": ["username", "password"],
            "properties": {
                "username": {"type": "string"},
                "password": {"type": "string", "format": "password"},
            },
        },
        "LoginResponse": {
            "type": "object",
            "properties": {
                "success": {"type": "boolean"},
                "token": {"type": "string"},
                "token_type": {"type": "string"},
                "expires_at": {"type": "string"},
                "user": {"type": "object"},
            },
        },
        "ScanRequest": {
            "type": "object",
            "required": ["domain"],
            "properties": {
                "domain": {"type": "string"},
                "intel": {"type": "boolean", "default": False},
                "enrich": {"type": "boolean", "default": False},
                "persist": {"type": "boolean", "default": True},
            },
        },
        "ScanResult": {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "phishing": {"type": "object"},
                "domain_squatting": {"type": "array", "items": {"type": "object"}},
                "brand_alerts": {"type": "array", "items": {"type": "object"}},
                "intel": {"type": "object"},
                "enrichment": {"type": "object"},
                "analyzed_at": {"type": "string"},
            },
        },
        "BulkScanRequest": {
            "type": "object",
            "required": ["domains"],
            "properties": {"domains": {"type": "array", "items": {"type": "string"}}},
        },
        "PermutationRequest": {
            "type": "object",
            "required": ["brand"],
            "properties": {
                "brand": {"type": "string"},
                "tlds": {"type": "array", "items": {"type": "string"}},
                "detailed": {"type": "boolean"},
                "include_combos": {"type": "boolean"},
                "limit": {"type": "integer"},
            },
        },
        "Alert": {
            "type": "object",
            "properties": {
                "alert_id": {"type": "string"},
                "brand_name": {"type": "string"},
                "alert_type": {"type": "string"},
                "severity": _SEVERITY,
                "status": _STATUS,
                "domain": {"type": "string"},
                "description": {"type": "string"},
                "evidence": {"type": "object"},
                "created_at": {"type": "string"},
                "assignee": {"type": "string", "nullable": True},
                "notes": {"type": "string"},
            },
        },
        "AlertList": {
            "type": "object",
            "properties": {
                "alerts": {"type": "array", "items": {"$ref": "#/components/schemas/Alert"}},
                "total": {"type": "integer"},
                "limit": {"type": "integer"},
                "offset": {"type": "integer"},
            },
        },
        "AlertUpdate": {
            "type": "object",
            "properties": {
                "status": _STATUS,
                "assignee": {"type": "string"},
                "notes": {"type": "string"},
            },
        },
        "AllowlistRequest": {
            "type": "object",
            "required": ["domain"],
            "properties": {"domain": {"type": "string"}, "reason": {"type": "string"}},
        },
        "SightingUpdate": {
            "type": "object",
            "required": ["status"],
            "properties": {
                "status": {
                    "type": "string",
                    "enum": ["new", "monitoring", "takedown_requested", "resolved", "benign"],
                }
            },
        },
        "SquatCheckRequest": {
            "type": "object",
            "required": ["brand"],
            "properties": {
                "brand": {"type": "string"},
                "tlds": {"type": "array", "items": {"type": "string"}},
                "limit": {"type": "integer", "default": 200},
            },
        },
    }

    return {
        "openapi": "3.0.3",
        "info": {
            "title": "BrandSentra API",
            "version": __version__,
            "description": "Digital risk protection & brand intelligence suite. Mutating endpoints require a bearer token from /api/v1/auth/login or an X-API-Key header.",
            "license": {"name": "MIT"},
        },
        "servers": [{"url": base_url}],
        "tags": [
            {"name": t}
            for t in (
                "system",
                "auth",
                "scan",
                "brands",
                "alerts",
                "allowlist",
                "intel",
                "squats",
                "reports",
            )
        ],
        "paths": paths,
        "components": {
            "schemas": schemas,
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer"},
                "apiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
            },
        },
    }


SWAGGER_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>BrandSentra API</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
<style>body{margin:0;background:#0a1628}.topbar{display:none}</style></head>
<body><div id="swagger-ui"></div>
<script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>window.onload=()=>SwaggerUIBundle({url:'/api/v1/openapi.json',dom_id:'#swagger-ui'});</script>
</body></html>
"""

__all__ = ["SWAGGER_HTML", "build_spec"]
