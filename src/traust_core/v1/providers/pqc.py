from __future__ import annotations

import hashlib
import os
import tempfile
from collections.abc import Callable
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Protocol

from pydantic import Field, field_validator

from traust_core.v1.errors import (
    ConfigError,
    IntegrityError,
    ServiceError,
    TraustError,
    ValidationError,
)
from traust_core.v1.models.base import Dto
from traust_core.v1.models.common import ToolRequest
from traust_core.v1.models.pqc import PqcScan, PqcScanFinding, PqcStamps
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.process import ProcessResult, ProcessRunner

MAX_REPORT_BYTES = 16 << 20
MAX_CBOM_BYTES = 16 << 20
MAX_FINDINGS = 50_000
MAX_PROCESS_OUTPUT_BYTES = 1 << 20


class PqcOutputLimit(ServiceError):
    pass


class PqcScanError(ServiceError):
    def __init__(self, result: ProcessResult) -> None:
        super().__init__(f"pqc-scan failed (exit {result.returncode})")
        self.result = result


class PqcScanner(Protocol):
    """The pinned Layer-1 scanner: raw rule hits over a checkout, stamped with its pack."""

    name: str

    def check(self) -> Readiness: ...

    def stamps(self) -> PqcStamps:
        """What a scan by the current binary and rules pack would be stamped with."""
        ...

    def scan(self, request: ToolRequest) -> Result[PqcScan]: ...


class ScannerSummary(Dto):
    scanned_files: int = Field(ge=0, strict=True)
    skipped_files: int = Field(ge=0, strict=True)


class ScannerReport(Dto):
    summary: ScannerSummary
    findings: tuple[dict[str, object], ...]

    @field_validator("findings", mode="before")
    @classmethod
    def _within_budget(cls, value: object) -> object:
        if isinstance(value, (list, tuple)) and len(value) > MAX_FINDINGS:
            raise PqcOutputLimit(f"pqc-scan findings exceed the {MAX_FINDINGS} finding limit")
        return value


class PqcScanTool:
    name = "pqc-scan"

    def __init__(
        self,
        process: ProcessRunner,
        clock: Clock,
        binary: Path,
        rules: Path,
        *,
        adapter_version: str,
        scan_commit: str,
        load_yaml: Callable[[str], list[object]],
    ) -> None:
        self._process, self._clock = process, clock
        self._binary, self._rules = binary.resolve(), rules.resolve()
        self._adapter_version, self._scan_commit = adapter_version, scan_commit
        self._load_yaml = load_yaml

    def check(self) -> Readiness:
        if not self._process.allows(str(self._binary)):
            return Readiness(ready=False, detail="pqc-scan is not in process.allowed_binaries")
        try:
            if self.stamps().binary_sha256 is None:
                return Readiness(ready=False, detail=f"pqc-scan binary is missing: {self._binary}")
            if not os.access(self._binary, os.X_OK):
                return Readiness(ready=False, detail="pqc-scan binary is not executable")
        except (OSError, TraustError) as exc:
            return Readiness(ready=False, detail=str(exc))
        return Readiness(ready=True)

    def _rule_files(self) -> list[Path]:
        return sorted(
            file
            for file in self._rules.rglob("*")
            if file.is_file() and not file.is_symlink() and file.suffix in {".yml", ".yaml"}
        )

    def stamps(self) -> PqcStamps:
        files = self._rule_files()
        if not files:
            raise ConfigError(f"pqc-scan rules pack is empty: {self._rules}")
        digest = hashlib.sha256()
        for file in files:
            digest.update(file.relative_to(self._rules).as_posix().encode())
            digest.update(b"\0")
            with file.open("rb") as stream:
                digest.update(hashlib.file_digest(stream, "sha256").digest())
        binary_sha = None
        if self._binary.is_file():
            with self._binary.open("rb") as stream:
                binary_sha = hashlib.file_digest(stream, "sha256").hexdigest()
            recorded = self._binary.with_suffix(".sha256").read_text().split()
            if not recorded or recorded[0] != binary_sha:
                raise IntegrityError("pqc-scan binary does not match its recorded checksum")
        return PqcStamps(
            adapter_version=self._adapter_version,
            pqc_scan_commit=self._scan_commit,
            rules_sha256=digest.hexdigest(),
            binary_sha256=binary_sha,
        )

    def scan(self, request: ToolRequest) -> Result[PqcScan]:
        stamps = self.stamps()
        if stamps.binary_sha256 is None:
            raise ConfigError(f"pqc-scan binary is missing: {self._binary}")
        rules = 0
        for file in self._rule_files():
            try:
                documents = self._load_yaml(file.read_text())
            except (OSError, ValidationError) as exc:
                raise ConfigError(f"pqc-scan rules could not be read: {file}") from exc
            if len(documents) != 1 or not isinstance(documents[0], (dict, list)):
                raise ConfigError(f"pqc-scan rules must be a mapping or sequence: {file}")
            document = documents[0]
            rules += len(document) if isinstance(document, list) else 1
        if rules == 0:
            raise ConfigError("pqc-scan pack has no rules")
        with tempfile.TemporaryDirectory(prefix="pqc-scan-") as directory:
            output = Path(directory)
            done = self._process.run(
                [
                    str(self._binary),
                    "scan",
                    str(request.checkout()),
                    "--rules-dir",
                    str(self._rules),
                    "--format",
                    "all",
                    "--out-dir",
                    str(output),
                ],
                check=False,
                timeout_seconds=1800,
                max_output_bytes=MAX_PROCESS_OUTPUT_BYTES,
            )
            if done.returncode != 0:
                raise PqcScanError(done)
            try:
                raw = ScannerReport.model_validate_json(
                    _read_output(output / "report.json", MAX_REPORT_BYTES, "report")
                )
                findings = tuple(_finding(item) for item in raw.findings)
            except (OSError, ValueError, TypeError, KeyError) as exc:
                raise ValidationError("pqc-scan produced a missing or malformed report") from exc
            if self.stamps() != stamps:
                raise IntegrityError("pqc-scan binary or rules changed while scanning")
            cbom = output / "cbom.json"
            scan = PqcScan(
                findings=findings,
                scanned_files=raw.summary.scanned_files,
                skipped_files=raw.summary.skipped_files,
                rules_in_pack=rules,
                stamps=stamps,
                cbom=_read_output(cbom, MAX_CBOM_BYTES, "CBOM") if cbom.is_file() else None,
            )
        return Result(
            scan,
            Acquisition(
                provider=self.name,
                acquired_at=self._clock.now(),
                version=self._scan_commit,
                source=str(request.checkout()),
            ),
        )


def _read_output(path: Path, maximum: int, label: str) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise PqcOutputLimit(f"pqc-scan {label} exceeds the {maximum} byte limit")
    return data


def _finding(item: dict[str, object]) -> PqcScanFinding:
    location = item.get("location")
    evidence = item.get("evidence") or {}
    if not isinstance(location, dict) or not isinstance(evidence, dict):
        raise ValidationError("pqc-scan finding has invalid location or evidence")
    file = location.get("file")
    if not isinstance(file, str) or not file.strip():
        raise ValidationError("pqc-scan finding has no source file")
    path = PurePosixPath(file.replace("\\", "/"))
    if (
        path.is_absolute()
        or PureWindowsPath(file).drive
        or path == PurePosixPath(".")
        or ".." in path.parts
        or any(ord(char) < 32 or ord(char) == 127 for char in file)
    ):
        raise ValidationError("pqc-scan finding has an invalid source file")
    line = location.get("line")
    if line is not None and (type(line) is not int or line < 1):
        raise ValidationError("pqc-scan finding has an invalid source line")
    return PqcScanFinding.model_validate(
        {
            "rule_id": item["rule_id"],
            "file": file,
            "line": line,
            "finding_id": item.get("finding_id"),
            "severity": item.get("severity"),
            "risk": item.get("risk"),
            "confidence": item.get("confidence"),
            "detail": str(item.get("description") or "")[:200],
            "match": str(evidence.get("match") or item.get("source_snippet") or "")[:120],
        }
    )
