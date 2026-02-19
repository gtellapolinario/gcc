from __future__ import annotations

import pytest

pytest.importorskip("mcp")

from gcc_mcp import server


def test_build_fastmcp_keeps_optional_kwargs_when_supported(monkeypatch) -> None:
    captured: dict[str, object] = {}

    class FakeFastMCP:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

    monkeypatch.setattr(server, "FastMCP", FakeFastMCP)
    instance = server._build_fastmcp()

    assert isinstance(instance, FakeFastMCP)
    assert captured["name"] == "git-context-controller"
    assert captured["version"] == "0.1.0"
    assert captured["json_response"] is True


def test_build_fastmcp_drops_unsupported_optional_kwargs(monkeypatch) -> None:
    calls: list[dict[str, object]] = []

    class FakeFastMCP:
        def __init__(self, **kwargs: object) -> None:
            calls.append(dict(kwargs))
            if "version" in kwargs:
                raise TypeError(
                    "FastMCP.__init__() got an unexpected keyword argument 'version'"
                )
            if "json_response" in kwargs:
                raise TypeError(
                    "FastMCP.__init__() got an unexpected keyword argument 'json_response'"
                )

    monkeypatch.setattr(server, "FastMCP", FakeFastMCP)
    instance = server._build_fastmcp()

    assert isinstance(instance, FakeFastMCP)
    assert len(calls) == 3
    assert "version" in calls[0]
    assert "json_response" in calls[0]
    assert "version" not in calls[1]
    assert "json_response" in calls[1]
    assert "version" not in calls[2]
    assert "json_response" not in calls[2]


def test_build_fastmcp_re_raises_unrelated_type_errors(monkeypatch) -> None:
    class FakeFastMCP:
        def __init__(self, **kwargs: object) -> None:
            _ = kwargs
            raise TypeError("boom")

    monkeypatch.setattr(server, "FastMCP", FakeFastMCP)
    with pytest.raises(TypeError, match="boom"):
        server._build_fastmcp()
