"""Consumers install traust-core without the [s3] extra: only the S3 adapter may need it."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src"
BLOCK = """
import importlib.abc, pkgutil, sys
class Block(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in {"boto3", "botocore"}:
            raise ModuleNotFoundError(f"No module named {name!r} (blocked)", name=name)
sys.meta_path.insert(0, Block())
import traust_core
for m in pkgutil.walk_packages(traust_core.__path__, "traust_core."):
    if not m.name.endswith(".objects.s3"):
        __import__(m.name)
try:
    import traust_core.v1.repositories.objects.s3
except ModuleNotFoundError:
    pass
else:
    raise AssertionError("the adapter requires the optional SDK")
"""


def test_core_imports_without_the_s3_extra_but_the_adapter_requires_it() -> None:
    done = subprocess.run(
        [sys.executable, "-c", BLOCK], capture_output=True, text=True, check=False, cwd=SRC
    )
    assert done.returncode == 0, done.stderr


def test_selected_s3_requires_the_optional_sdk() -> None:
    code = (
        BLOCK
        + """
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConfigError
try:
    Context(Config.model_validate({"artifacts": {"s3": {"bucket": "test-artifacts"}}})).object_store
except ConfigError as e:
    assert "traust-core[s3]" in str(e)
else:
    raise AssertionError("S3 selection needs the optional SDK")
"""
    )
    done = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=False, cwd=SRC
    )
    assert done.returncode == 0, done.stderr
