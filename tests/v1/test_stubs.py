import ast
import importlib
import inspect
import pkgutil
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

import traust_core.v1 as v1


def _is_stub(node: ast.FunctionDef) -> bool:
    body = [n for n in node.body if not isinstance(n, ast.Expr)]
    if len(body) != 1 or not isinstance(body[0], ast.Raise):
        return False
    exc = body[0].exc
    return (
        isinstance(exc, ast.Call)
        and getattr(exc.func, "id", None) == "NotImplementedError"
        and bool(exc.args)
        and "stub" in ast.unparse(exc.args[0])
    )


def _stubs() -> Iterator[tuple[str, Callable[..., Any]]]:
    for info in pkgutil.walk_packages(v1.__path__, "traust_core.v1."):
        module = importlib.import_module(info.name)
        tree = ast.parse(Path(inspect.getfile(module)).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and _is_stub(node) and node.col_offset == 0:
                yield info.name, getattr(module, node.name)
        for cls_node in (n for n in tree.body if isinstance(n, ast.ClassDef)):
            cls = getattr(module, cls_node.name)
            for fn in (n for n in cls_node.body if isinstance(n, ast.FunctionDef)):
                if _is_stub(fn):
                    yield f"{info.name}.{cls_node.name}", inspect.getattr_static(cls, fn.name)


STUBS = sorted(_stubs(), key=lambda s: (s[0], getattr(s[1], "__qualname__", "")))


def _callable(owner: str, member: Any) -> Callable[..., Any]:
    if isinstance(member, classmethod | staticmethod):
        return member.__get__(None, _owner_class(owner))
    if inspect.isclass(owner_obj := _resolve(owner)):
        return member.__get__(object.__new__(owner_obj), owner_obj)
    return member


def _resolve(owner: str) -> Any:
    try:
        return importlib.import_module(owner)
    except ModuleNotFoundError:
        return _owner_class(owner)


def _owner_class(owner: str) -> type:
    module, _, name = owner.rpartition(".")
    return getattr(importlib.import_module(module), name)


def _id(stub: tuple[str, Any]) -> str:
    fn = stub[1].__func__ if isinstance(stub[1], classmethod | staticmethod) else stub[1]
    return f"{stub[0].removeprefix('traust_core.v1.')}::{fn.__name__}"


@pytest.mark.parametrize("stub", STUBS, ids=_id)
def test_stub_raises_not_implemented(stub: tuple[str, Any]) -> None:
    owner, member = stub
    fn = _callable(owner, member)
    params = list(inspect.signature(fn).parameters)
    with pytest.raises(NotImplementedError, match="stub"):
        fn(*[None] * len(params))


@pytest.mark.parametrize("stub", STUBS, ids=_id)
def test_stub_signature_is_fully_typed(stub: tuple[str, Any]) -> None:
    member = stub[1]
    fn = member.__func__ if isinstance(member, classmethod | staticmethod) else member
    sig = inspect.signature(fn)
    params = [p for p in sig.parameters.values() if p.name not in ("self", "cls")]
    untyped = [p for p in params if p.annotation is p.empty]
    assert not untyped, f"untyped parameters: {untyped}"
    assert sig.return_annotation is not sig.empty, "missing return annotation"


def test_every_domain_has_stubs() -> None:
    roles = {owner.split(".")[2] for owner, _ in STUBS}
    assert {"models", "services", "context"} <= roles
    assert "repositories" not in roles  # one real repository per contract table, no stubs
