from __future__ import annotations

import pytest

pytest.importorskip("mcp")

from gcc_mcp.auth import OAuth2IntrospectionTokenVerifier


@pytest.mark.parametrize(
    "url",
    [
        "ftp://auth.example.com/introspect",
        "https:///introspect",
        "https://user:pass@auth.example.com/introspect",
        "https://auth.example.com/introspect#fragment",
    ],
)
def test_oauth2_introspection_verifier_rejects_unsafe_urls(url: str) -> None:
    with pytest.raises(ValueError):
        OAuth2IntrospectionTokenVerifier(introspection_url=url)


def test_oauth2_introspection_verifier_builds_request_target() -> None:
    verifier = OAuth2IntrospectionTokenVerifier(
        introspection_url="https://auth.example.com/oauth2/introspect?realm=prod",
    )
    assert verifier._introspection_target == "/oauth2/introspect?realm=prod"
