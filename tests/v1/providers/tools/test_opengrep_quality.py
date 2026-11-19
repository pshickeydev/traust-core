from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from tests.v1.conftest import NoCheckouts
from tests.v1.providers.tools.opengrep_fixtures import native_output, write_rule
from traust_core.v1.context.documents import yaml_documents
from traust_core.v1.errors import ValidationError
from traust_core.v1.providers.process import ProcessResult, ProcessRunner
from traust_core.v1.providers.tools.opengrep import SupplementalPack, execute_scan
from traust_core.v1.providers.tools.opengrep_quality import RuleQualityError, checked_rules


class NativeRunner:
    def __init__(self, failure: str = "") -> None:
        self.failure = failure
        self.scanned = False

    def run(self, argv, **kwargs) -> ProcessResult:
        args = tuple(argv)
        output = native_output(args)
        code = 0
        if args[1] == "validate":
            if self.failure == "validate-exit":
                code = 123
            elif self.failure == "validate-skipped":
                output = b"0 fatal errors, 1 skippable error(s)"
        elif args[1] == "test":
            if self.failure == "test-exit":
                code = 123
            data = json.loads(output)
            checks = next(iter(data["results"].values()))["checks"]
            check = next(iter(checks.values()))
            if self.failure == "test-empty":
                data["results"] = {}
            elif self.failure == "test-unexpected":
                next(iter(check["matches"].values()))["reported_lines"].append(99)
            elif self.failure == "test-errors":
                check["errors"] = ["partial parse"]
            elif self.failure == "test-missing-fixture":
                data["config_missing_tests"] = ["rules.yaml"]
            elif self.failure == "test-wrong-type":
                check["passed"] = "true"
            output = json.dumps(data).encode()
        elif args[1] == "scan":
            self.scanned = True
            output = b'{"results":[],"errors":[],"paths":{"scanned":["app.py"]}}'
            if self.failure == "scan-exit":
                code = 7
        elif args[1] == "--version":
            output = b"1.25.0"
        return ProcessResult(args, code, output or b"", b"", 0.01)


@pytest.mark.parametrize(
    "failure",
    [
        "validate-exit",
        "validate-skipped",
        "test-exit",
        "test-empty",
        "test-unexpected",
        "test-errors",
        "test-missing-fixture",
        "test-wrong-type",
    ],
)
def test_failed_native_quality_never_scans_the_checkout(tmp_path: Path, failure: str) -> None:
    config = write_rule(tmp_path / "pack")
    target = tmp_path / "checkout"
    target.mkdir()
    (target / "app.py").write_text("dangerous(value)\n")
    runner = NativeRunner(failure)
    with pytest.raises(RuleQualityError):
        execute_scan(
            target,
            [],
            pack=config.parent,
            runner=runner,
            checkouts=NoCheckouts(),
            load=yaml_documents,
        )
    assert not runner.scanned


@pytest.mark.parametrize(
    "example",
    ["# ruleid: example-rule\ndangerous(value)\n", "# ok: example-rule\nsafe(value)\n"],
)
def test_native_success_without_both_behavior_directions_is_refused(
    tmp_path: Path, example: str
) -> None:
    config = write_rule(tmp_path / "pack")
    config.with_suffix(".py").write_text(example)
    with checked_rules([config.parent], NativeRunner(), load=yaml_documents) as checked:
        assert not checked.report.passed
        assert "both ruleid: and ok:" in checked.report.checks[-1].detail


def test_duplicate_rule_ids_are_not_an_ambiguous_pack(tmp_path: Path) -> None:
    write_rule(tmp_path, name="first")
    write_rule(tmp_path, name="second")
    with checked_rules([tmp_path], NativeRunner(), load=yaml_documents) as checked:
        assert not checked.report.passed
        assert "duplicate rule id" in checked.report.checks[0].detail


def test_a_fixture_cannot_read_outside_the_pack(tmp_path: Path) -> None:
    config = write_rule(tmp_path / "pack")
    config.with_suffix(".py").unlink()
    outside = tmp_path / "outside.py"
    outside.write_text("private = 1\n")
    config.with_suffix(".py").symlink_to(outside)
    with (
        pytest.raises(ValidationError, match="leaves its source directory"),
        checked_rules([config.parent], NativeRunner(), load=yaml_documents),
    ):
        pass


def test_an_abnormal_scan_exit_is_not_accepted_because_json_exists(tmp_path: Path) -> None:
    config = write_rule(tmp_path / "pack")
    with pytest.raises(RuntimeError, match="exited 7"):
        execute_scan(
            tmp_path,
            [],
            pack=config.parent,
            runner=NativeRunner("scan-exit"),
            checkouts=NoCheckouts(),
            load=yaml_documents,
        )


@pytest.mark.skipif(not shutil.which("opengrep"), reason="real Opengrep integration")
def test_real_native_gate_enables_a_namespaced_local_adopter_rule(tmp_path: Path) -> None:
    builtin = write_rule(tmp_path / "builtin", "builtin-rule")
    custom = write_rule(tmp_path / "custom", "acme.security.rule")
    target = tmp_path / "checkout"
    target.mkdir()
    (target / "app.py").write_text("dangerous(value)\nsafe(value)\n")
    result = execute_scan(
        target,
        [],
        pack=builtin.parent,
        runner=ProcessRunner(("opengrep",)),
        checkouts=NoCheckouts(),
        load=yaml_documents,
        supplements=(SupplementalPack("acme", str(custom.parent), ("acme.security.rule",)),),
    )
    assert {fact["rule_id"] for fact in result["facts"]} == {"builtin-rule", "acme.security.rule"}
    assert result["supplemental_packs"]["applied"] == ["acme"]
    assert all(check["passed"] for check in result["quality_checks"])


@pytest.mark.skipif(not shutil.which("opengrep"), reason="real Opengrep integration")
def test_invalid_adopter_behavior_does_not_fall_back_to_builtin_rules(tmp_path: Path) -> None:
    builtin = write_rule(tmp_path / "builtin", "builtin-rule")
    custom = write_rule(tmp_path / "custom", "acme-rule")
    fixture = custom.with_suffix(".py")
    fixture.write_text(fixture.read_text().replace("safe(value)", "dangerous(value)"))
    target = tmp_path / "checkout"
    target.mkdir()
    (target / "app.py").write_text("dangerous(value)\n")
    with pytest.raises(RuleQualityError):
        execute_scan(
            target,
            [],
            pack=builtin.parent,
            runner=ProcessRunner(("opengrep",)),
            checkouts=NoCheckouts(),
            load=yaml_documents,
            supplements=(SupplementalPack("acme", str(custom.parent), ("acme-rule",)),),
        )
