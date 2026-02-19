"""Authentication helpers for streamable HTTP runtime modes."""

from __future__ import annotations

import asyncio
import base64
import http.client
import hmac
import json
import logging
import time
from typing import Any
from urllib.parse import urlencode, urlparse

from mcp.server.auth.provider import AccessToken
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger(__name__)


class StaticTokenVerifier:
    """Validate bearer tokens against a static shared secret."""

    def __init__(
        self,
        expected_token: str,
        scopes: list[str] | None = None,
        client_id: str = "gcc-static-token",
    ) -> None:
        self._expected_token = expected_token
        self._scopes = scopes or []
        self._client_id = client_id

    async def verify_token(self, token: str) -> AccessToken | None:
        if not token:
            return None
        if not hmac.compare_digest(token, self._expected_token):
            return None
        return AccessToken(
            token=token,
            client_id=self._client_id,
            scopes=list(self._scopes),
        )


class OAuth2IntrospectionTokenVerifier:
    """Validate bearer tokens using RFC 7662-style token introspection."""

    def __init__(
        self,
        introspection_url: str,
        timeout_seconds: float = 5.0,
        client_id: str = "",
        client_secret: str | None = None,
        required_scopes: list[str] | None = None,
    ) -> None:
        parsed = _parse_introspection_url(introspection_url)
        self._introspection_url = introspection_url
        self._introspection_scheme = parsed.scheme
        self._introspection_host = parsed.hostname or ""
        self._introspection_port = parsed.port
        self._introspection_target = _build_request_target(parsed)
        self._timeout_seconds = timeout_seconds
        self._client_id = client_id
        self._client_secret = client_secret or ""
        self._required_scopes = required_scopes or []

    async def verify_token(self, token: str) -> AccessToken | None:
        if not token:
            return None

        try:
            payload = await asyncio.to_thread(self._introspect, token)
        except Exception:  # noqa: BLE001
            logger.warning("OAuth2 introspection failed.", exc_info=True)
            return None

        if not _is_token_active(payload.get("active")):
            return None

        scopes = _coerce_scope_list(payload.get("scope") or payload.get("scopes"))
        if self._required_scopes and not set(self._required_scopes).issubset(set(scopes)):
            return None

        expires_at = _coerce_epoch_seconds(payload.get("exp"))
        if expires_at is not None and expires_at <= int(time.time()):
            return None

        client_id = str(payload.get("client_id") or self._client_id or "oauth2-client")

        return AccessToken(
            token=token,
            client_id=client_id,
            scopes=scopes,
            expires_at=expires_at,
            resource=_extract_resource(payload),
        )

    def _introspect(self, token: str) -> dict[str, Any]:
        body = urlencode({"token": token}).encode("utf-8")
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        if self._client_id and self._client_secret:
            client_creds = f"{self._client_id}:{self._client_secret}".encode("utf-8")
            headers["Authorization"] = f"Basic {base64.b64encode(client_creds).decode('ascii')}"

        response_bytes = self._post_form(body=body, headers=headers)
        payload = json.loads(response_bytes.decode("utf-8"))
        if isinstance(payload, dict):
            return payload
        return {}

    def _post_form(self, body: bytes, headers: dict[str, str]) -> bytes:
        connection_class = (
            http.client.HTTPSConnection
            if self._introspection_scheme == "https"
            else http.client.HTTPConnection
        )
        connection = connection_class(
            host=self._introspection_host,
            port=self._introspection_port,
            timeout=self._timeout_seconds,
        )
        try:
            connection.request(
                method="POST",
                url=self._introspection_target,
                body=body,
                headers=headers,
            )
            response = connection.getresponse()
            response_bytes = response.read()
            if response.status >= 400:
                raise ValueError(
                    f"Introspection endpoint returned HTTP {response.status}."
                )
            return response_bytes
        finally:
            connection.close()


class TrustedProxyHeaderMiddleware:
    """Require a pre-shared proxy header before forwarding requests."""

    def __init__(self, app: ASGIApp, header_name: str, expected_value: str) -> None:
        self._app = app
        self._header_name = header_name.strip().lower().encode("ascii")
        self._expected_value = expected_value

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        provided_value = ""
        for key, value in scope.get("headers", []):
            if key == self._header_name:
                provided_value = value.decode("latin-1")
                break

        if not hmac.compare_digest(provided_value, self._expected_value):
            response = JSONResponse(
                {
                    "status": "error",
                    "error_code": "UNAUTHORIZED",
                    "message": "Missing or invalid trusted proxy header.",
                    "suggestion": (
                        "Ensure Envoy injects the trusted proxy header before "
                        "forwarding requests to gcc-mcp."
                    ),
                    "details": {},
                },
                status_code=401,
            )
            await response(scope, receive, send)
            return

        await self._app(scope, receive, send)


def _coerce_scope_list(raw_scope: Any) -> list[str]:
    if isinstance(raw_scope, str):
        return [value.strip() for value in raw_scope.split() if value.strip()]
    if isinstance(raw_scope, list):
        values: list[str] = []
        for item in raw_scope:
            normalized = str(item).strip()
            if normalized:
                values.append(normalized)
        return values
    return []


def _is_token_active(raw_value: Any) -> bool:
    if isinstance(raw_value, bool):
        return raw_value
    if isinstance(raw_value, (int, float)):
        return raw_value != 0
    normalized = str(raw_value).strip().lower()
    return normalized in {"1", "true", "yes", "on"}


def _coerce_epoch_seconds(raw_expiration: Any) -> int | None:
    if raw_expiration is None:
        return None
    if isinstance(raw_expiration, (int, float)):
        return int(raw_expiration)
    normalized = str(raw_expiration).strip()
    if not normalized:
        return None
    try:
        return int(normalized)
    except ValueError:
        return None


def _extract_resource(payload: dict[str, Any]) -> str | None:
    resource_value = payload.get("resource")
    if isinstance(resource_value, str) and resource_value.strip():
        return resource_value.strip()

    audience = payload.get("aud")
    if isinstance(audience, str) and audience.strip():
        return audience.strip()
    if isinstance(audience, list):
        for item in audience:
            normalized = str(item).strip()
            if normalized:
                return normalized
    return None


def _parse_introspection_url(url: str):
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("introspection_url must use http or https.")
    if not parsed.hostname:
        raise ValueError("introspection_url must include a hostname.")
    if parsed.username or parsed.password:
        raise ValueError("introspection_url must not contain embedded credentials.")
    if parsed.fragment:
        raise ValueError("introspection_url must not contain a fragment.")
    return parsed


def _build_request_target(parsed_url) -> str:
    target = parsed_url.path or "/"
    if parsed_url.query:
        target = f"{target}?{parsed_url.query}"
    return target
