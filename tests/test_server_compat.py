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


def test_register_tool_coerces_non_class_annotations(monkeypatch) -> None:
    calls: list[dict[str, object]] = []

    class FakeMCP:
        def tool(self, annotations: dict[str, bool] | None = None):
            def decorator(func):
                call = {
                    "annotations": annotations,
                    "parameter_annotation": func.__annotations__["values"],
                    "return_annotation": func.__annotations__["return"],
                }
                calls.append(call)
                if not all(
                    isinstance(annotation, type) for annotation in func.__annotations__.values()
                ):
                    raise TypeError("issubclass() arg 1 must be a class")
                return func

            return decorator

    monkeypatch.setattr(server, "mcp", FakeMCP())

    @server._register_tool(server.WRITE_TOOL_ANNOTATIONS)
    def _sample(values: list[str] | None = None) -> dict[str, object]:
        return {"values": values}

    assert _sample(values=["a"]) == {"values": ["a"]}
    assert len(calls) == 2
    assert calls[0]["annotations"] == server.WRITE_TOOL_ANNOTATIONS
    assert calls[1]["annotations"] == server.WRITE_TOOL_ANNOTATIONS
    assert calls[1]["parameter_annotation"] is list
    assert calls[1]["return_annotation"] is dict
    assert not isinstance(_sample.__annotations__["values"], type)


def test_register_tool_coerces_non_class_annotations_without_tool_annotations(
    monkeypatch,
) -> None:
    calls: list[dict[str, object]] = []

    class FakeMCP:
        def tool(self, annotations: dict[str, bool] | None = None):
            def decorator(func):
                calls.append(
                    {
                        "annotations": annotations,
                        "parameter_annotation": func.__annotations__["values"],
                    }
                )
                if annotations is not None:
                    raise TypeError("got an unexpected keyword argument 'annotations'")
                if not all(
                    isinstance(annotation, type) for annotation in func.__annotations__.values()
                ):
                    raise TypeError("issubclass() arg 1 must be a class")
                return func

            return decorator

    monkeypatch.setattr(server, "mcp", FakeMCP())

    @server._register_tool(server.WRITE_TOOL_ANNOTATIONS)
    def _sample(values: list[str] | None = None) -> dict[str, object]:
        return {"values": values}

    assert _sample(values=["a"]) == {"values": ["a"]}
    assert len(calls) == 3
    assert calls[0]["annotations"] == server.WRITE_TOOL_ANNOTATIONS
    assert calls[1]["annotations"] is None
    assert calls[2]["annotations"] is None
    assert calls[2]["parameter_annotation"] is list


def test_register_tool_re_raises_unrelated_type_errors(monkeypatch) -> None:
    class FakeMCP:
        def tool(self, annotations: dict[str, bool] | None = None):
            _ = annotations

            def decorator(func):
                _ = func
                raise TypeError("boom")

            return decorator

    monkeypatch.setattr(server, "mcp", FakeMCP())

    def _sample(values: list[str] | None = None) -> dict[str, object]:
        return {"values": values}

    with pytest.raises(TypeError, match="boom"):
        server._register_tool(server.WRITE_TOOL_ANNOTATIONS)(_sample)
