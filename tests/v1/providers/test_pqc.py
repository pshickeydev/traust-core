from __future__ import annotations

import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import traust_core.v1.providers.pqc as pqc_provider
from traust_core.v1.context import Config, Context
from traust_core.v1.context.documents import yaml_documents
from traust_core.v1.errors import ConfigError, IntegrityError, ServiceError, ValidationError
from traust_core.v1.models.common import ToolRequest
from traust_core.v1.models.inventory import RefName
from traust_core.v1.models.pqc import PqcFilter
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.models.vocabulary import RefKind
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.pqc import PqcOutputLimit, PqcScanError, PqcScanTool
from traust_core.v1.providers.process import ProcessOutputLimit, ProcessRunner

AT = datetime(2026, 10, 24, tzinfo=UTC)


def scanner(
    tmp_path: Path,
    report: object,
    *,
    code: int = 0,
    stdout: bytes = b"",
    stderr: bytes = b"",
    cbom: bytes = b"cbom-fixture",
) -> PqcScanTool:
    binary = tmp_path / "pqc-scan"
    binary.write_text(
        f"#!{sys.executable}\n"
        "import pathlib, sys\n"
        "output = pathlib.Path(sys.argv[sys.argv.index('--out-dir') + 1])\n"
        f"(output / 'report.json').write_text({json.dumps(report)!r})\n"
        f"(output / 'cbom.json').write_bytes({cbom!r})\n"
        f"sys.stdout.buffer.write({stdout!r})\n"
        f"sys.stderr.buffer.write({stderr!r})\n"
        f"sys.exit({code})\n"
    )
    binary.chmod(0o700)
    binary.with_suffix(".sha256").write_text(hashlib.sha256(binary.read_bytes()).hexdigest())
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "one.yml").write_text("- id: API_RSA\n  pattern: rsa\n")
    return PqcScanTool(
        ProcessRunner(["pqc-scan"]),
        FixedClock(AT),
        binary,
        rules,
        adapter_version="1.4.0",
        scan_commit="be5c760",
        load_yaml=yaml_documents,
    )


def test_real_process_output_becomes_stamped_facts_not_a_readiness_score(tmp_path: Path) -> None:
    provider = scanner(
        tmp_path,
        {
            "summary": {"scanned_files": 2, "skipped_files": 1},
            "findings": [
                {
                    "rule_id": "API_RSA",
                    "description": "RSA signing",
                    "location": {"file": "keys.go", "line": 4},
                    "evidence": {"match": "rsa.GenerateKey"},
                }
            ],
        },
    )
    result = provider.scan(ToolRequest(workspace=tmp_path))
    assert result.acquisition.acquired_at == AT
    assert (result.data.scanned_files, result.data.skipped_files, result.data.rules_in_pack) == (
        2,
        1,
        1,
    )
    assert [(f.rule_id, f.file, f.line, f.match) for f in result.data.findings] == [
        ("API_RSA", "keys.go", 4, "rsa.GenerateKey"),
    ]
    assert result.data.stamps == provider.stamps()
    assert result.data.cbom == b"cbom-fixture"
    assert provider.check().ready


@pytest.mark.parametrize(
    "report",
    [
        {},
        {"summary": {"scanned_files": 1, "skipped_files": 0}},
        {"summary": {"scanned_files": -1, "skipped_files": 0}, "findings": []},
        {"summary": {"scanned_files": 1, "skipped_files": 0}, "findings": [{}]},
    ],
)
def test_incomplete_output_cannot_masquerade_as_a_clean_scan(
    tmp_path: Path, report: object
) -> None:
    provider = scanner(tmp_path, report)
    with pytest.raises(ValidationError):
        provider.scan(ToolRequest(workspace=tmp_path))


def test_nonzero_exit_is_not_accepted_even_with_a_report(tmp_path: Path) -> None:
    provider = scanner(
        tmp_path,
        {
            "summary": {"scanned_files": 1, "skipped_files": 0},
            "findings": [],
        },
        code=7,
    )
    with pytest.raises(ServiceError):
        provider.scan(ToolRequest(workspace=tmp_path))


def test_binary_checksum_and_empty_rules_are_hard_boundaries(tmp_path: Path) -> None:
    provider = scanner(tmp_path, {})
    (tmp_path / "pqc-scan").write_text("changed binary")
    with pytest.raises(IntegrityError):
        provider.stamps()
    (tmp_path / "rules/one.yml").unlink()
    with pytest.raises(ConfigError):
        provider.stamps()
    assert not provider.check().ready


def test_registered_scanner_records_source_facts_and_reuses_the_same_pack(tmp_path: Path) -> None:
    scanner(
        tmp_path,
        {
            "summary": {"scanned_files": 1, "skipped_files": 0},
            "findings": [
                {
                    "rule_id": "API_RSA",
                    "description": "RSA signing",
                    "location": {"file": "keys.go", "line": 4},
                    "evidence": {"match": "rsa.GenerateKey"},
                }
            ],
        },
    )
    checkout = tmp_path / "source"
    checkout.mkdir()
    (checkout / "keys.go").write_text('package sample\nimport "crypto/rsa"\n')
    context = Context(
        Config(home=tmp_path / "state"), clock=FixedClock(AT), process=ProcessRunner(["pqc-scan"])
    )
    context.register_pqc_scanner(
        tmp_path / "pqc-scan",
        tmp_path / "rules",
        adapter_version="1.4.0",
        scan_commit="be5c760",
    )
    services = context.services()
    repository = services.portfolio.register_repository(
        HttpsRepoUrl.parse("https://github.com/example/widget", context.config.forge_hosts),
        public=False,
    )
    ref = services.portfolio.register_ref(
        repository.id, GitSha.parse("a" * 40), RefName("main"), RefKind.BRANCH
    )
    services.exposure.ingest_sbom(b'{"bomFormat": "CycloneDX", "components": []}', ref.id)
    request = ToolRequest(workspace=checkout)
    first = services.pqc.prescan(ref.id, request)
    assert first.scanned
    assert any(fact.rule_id == "API_RSA" and fact.file == "keys.go" for fact in first.facts)
    repeated = services.pqc.prescan(ref.id, request)
    assert repeated.assessment_id == first.assessment_id
    assert not repeated.scanned
    scope = PqcFilter(repository_ref_ids=(ref.id,))
    (state,) = services.pqc.scan_states(scope)
    assert (state.assessment_id, state.basis, state.current) == (
        first.assessment_id,
        "source",
        True,
    )
    nested = tmp_path / "rules" / "nested"
    nested.mkdir()
    (nested / "extra.yaml").write_text("id: EXTRA\npattern: ecdsa\n")
    (stale,) = services.pqc.scan_states(scope)
    assert stale.assessment_id == first.assessment_id
    assert stale.current is False


def test_nested_yaml_rules_change_pack_stamps_and_are_counted(tmp_path: Path) -> None:
    provider = scanner(
        tmp_path, {"summary": {"scanned_files": 1, "skipped_files": 0}, "findings": []}
    )
    initial = provider.stamps()
    nested = tmp_path / "rules" / "nested"
    nested.mkdir()
    rule = nested / "one.yaml"
    rule.write_text("id: NESTED\npattern: rsa\n")
    expanded = provider.stamps()
    assert not initial.same_pack(expanded)
    assert provider.scan(ToolRequest(workspace=tmp_path)).data.rules_in_pack == 2
    rule.write_text("id: NESTED\npattern: ecdsa\n")
    changed = provider.stamps()
    assert not expanded.same_pack(changed)
    relocated = tmp_path / "rules" / "other"
    relocated.mkdir()
    rule.rename(relocated / rule.name)
    assert not changed.same_pack(provider.stamps())


@pytest.mark.parametrize(
    "location",
    [
        None,
        {},
        {"file": ""},
        {"file": " \t"},
        {"file": "../outside.go", "line": 1},
        {"file": "/outside.go", "line": 1},
        {"file": "C:\\outside.go", "line": 1},
        {"file": "keys.go", "line": 0},
        {"file": "keys.go", "line": True},
        {"file": "keys.go", "line": "4"},
    ],
)
def test_malformed_source_locations_cannot_become_source_facts(
    tmp_path: Path, location: object
) -> None:
    finding = {"rule_id": "API_RSA"}
    if location is not None:
        finding["location"] = location
    provider = scanner(
        tmp_path,
        {"summary": {"scanned_files": 1, "skipped_files": 0}, "findings": [finding]},
    )
    with pytest.raises(ValidationError):
        provider.scan(ToolRequest(workspace=tmp_path))


@pytest.mark.parametrize("output", ["report", "cbom"])
def test_oversized_output_is_refused_before_becoming_scan_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, output: str
) -> None:
    report = {"summary": {"scanned_files": 1, "skipped_files": 0}, "findings": []}
    provider = scanner(tmp_path, report)
    if output == "report":
        monkeypatch.setattr(pqc_provider, "MAX_REPORT_BYTES", len(json.dumps(report).encode()) - 1)
    else:
        monkeypatch.setattr(pqc_provider, "MAX_CBOM_BYTES", len(b"cbom-fixture") - 1)
    with pytest.raises(PqcOutputLimit):
        provider.scan(ToolRequest(workspace=tmp_path))


def test_output_at_byte_limits_retains_coverage_and_cbom(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = {"summary": {"scanned_files": 1, "skipped_files": 0}, "findings": []}
    provider = scanner(tmp_path, report)
    monkeypatch.setattr(pqc_provider, "MAX_REPORT_BYTES", len(json.dumps(report).encode()))
    monkeypatch.setattr(pqc_provider, "MAX_CBOM_BYTES", len(b"cbom-fixture"))
    result = provider.scan(ToolRequest(workspace=tmp_path))
    assert result.data.scanned_files == 1
    assert result.data.cbom == b"cbom-fixture"


def test_finding_budget_refuses_excess_hits_before_fact_conversion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    provider = scanner(
        tmp_path,
        {
            "summary": {"scanned_files": 1, "skipped_files": 0},
            "findings": [
                {"rule_id": name, "location": {"file": "keys.go", "line": 1}}
                for name in ("FIRST", "SECOND")
            ],
        },
    )
    monkeypatch.setattr(pqc_provider, "MAX_FINDINGS", 1)
    with pytest.raises(PqcOutputLimit):
        provider.scan(ToolRequest(workspace=tmp_path))


def test_scanner_output_flood_is_a_bounded_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    provider = scanner(
        tmp_path,
        {"summary": {"scanned_files": 1, "skipped_files": 0}, "findings": []},
        stdout=b"x" * 256,
    )
    monkeypatch.setattr(pqc_provider, "MAX_PROCESS_OUTPUT_BYTES", 64)
    with pytest.raises(ProcessOutputLimit) as caught:
        provider.scan(ToolRequest(workspace=tmp_path))
    assert len(caught.value.result.stdout) + len(caught.value.result.stderr) <= 64


def test_failure_diagnostics_remain_internal_not_in_errors_or_logs(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    diagnostic = b"synthetic-scanner-secret: unsupported rule fixture"
    provider = scanner(
        tmp_path,
        {"summary": {"scanned_files": 1, "skipped_files": 0}, "findings": []},
        code=7,
        stderr=diagnostic,
    )
    caplog.set_level("DEBUG", logger="traust_core")
    with pytest.raises(PqcScanError) as caught:
        provider.scan(ToolRequest(workspace=tmp_path))
    assert caught.value.result.returncode == 7
    assert caught.value.result.stderr == diagnostic
    assert diagnostic.decode() not in str(caught.value)
    assert diagnostic.decode() not in caplog.text


def test_readiness_refuses_a_checksum_valid_non_executable_binary(tmp_path: Path) -> None:
    provider = scanner(
        tmp_path, {"summary": {"scanned_files": 1, "skipped_files": 0}, "findings": []}
    )
    assert provider.check().ready
    (tmp_path / "pqc-scan").chmod(0o600)
    assert not provider.check().ready


@pytest.mark.parametrize("change", ["binary", "commit"])
def test_approved_scanner_changes_invalidate_and_rescan_recorded_source_facts(
    tmp_path: Path, change: str
) -> None:
    scanner(
        tmp_path,
        {
            "summary": {"scanned_files": 1, "skipped_files": 0},
            "findings": [{"rule_id": "API_RSA", "location": {"file": "keys.go", "line": 1}}],
        },
    )
    checkout = tmp_path / "source"
    checkout.mkdir()
    context = Context(
        Config(home=tmp_path / "state"), clock=FixedClock(AT), process=ProcessRunner(["pqc-scan"])
    )
    binary = tmp_path / "pqc-scan"
    context.register_pqc_scanner(
        binary, tmp_path / "rules", adapter_version="1.4.0", scan_commit="original"
    )
    services = context.services()
    repository = services.portfolio.register_repository(
        HttpsRepoUrl.parse("https://github.com/example/scanner-change", context.config.forge_hosts),
        public=False,
    )
    ref = services.portfolio.register_ref(
        repository.id, GitSha.parse("b" * 40), RefName("main"), RefKind.BRANCH
    )
    services.exposure.ingest_sbom(b'{"bomFormat":"CycloneDX","components":[]}', ref.id)
    request = ToolRequest(workspace=checkout)
    first = services.pqc.prescan(ref.id, request)
    scope = PqcFilter(repository_ref_ids=(ref.id,))
    assert services.pqc.scan_states(scope)[0].current is True
    if change == "binary":
        binary.write_bytes(binary.read_bytes() + b"\n# approved rebuild\n")
        binary.with_suffix(".sha256").write_text(hashlib.sha256(binary.read_bytes()).hexdigest())
    context.clock = FixedClock(AT + timedelta(seconds=1))
    context.register_pqc_scanner(
        binary,
        tmp_path / "rules",
        adapter_version="1.4.0",
        scan_commit="replacement" if change == "commit" else "original",
    )
    services = context.services()
    stale = services.pqc.scan_states(scope)[0]
    assert stale.assessment_id == first.assessment_id and stale.current is False
    refreshed = services.pqc.prescan(ref.id, request)
    assert refreshed.scanned and refreshed.assessment_id != first.assessment_id
    current = services.pqc.scan_states(scope)[0]
    assert current.assessment_id == refreshed.assessment_id and current.current is True
