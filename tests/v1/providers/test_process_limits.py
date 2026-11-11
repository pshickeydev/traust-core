import hashlib
import logging
import sys
from pathlib import Path

import pytest

from traust_core.v1.errors import ValidationError
from traust_core.v1.providers.correlation import correlation_scope
from traust_core.v1.providers.process import (
    ProcessError,
    ProcessOutputLimit,
    ProcessRunner,
    ProcessTimeout,
)


@pytest.fixture
def runner() -> ProcessRunner:
    return ProcessRunner([Path(sys.executable).name], timeout_seconds=5)


@pytest.mark.parametrize("descriptor", [1, 2], ids=["stdout", "stderr"])
def test_output_flood_is_stopped_with_bounded_safe_diagnostics(
    runner: ProcessRunner, descriptor: int, caplog: pytest.LogCaptureFixture
) -> None:
    secret = "synthetic-sensitive-process-output"
    script = (
        f"import os; chunk = {secret.encode()!r} * 1024\nwhile True: os.write({descriptor}, chunk)"
    )
    with (
        caplog.at_level(logging.INFO, logger="traust_core.v1.providers.process"),
        pytest.raises(ProcessOutputLimit) as raised,
    ):
        runner.run([sys.executable, "-c", script], max_output_bytes=1024)
    error = raised.value
    assert error.max_output_bytes == 1024
    assert error.operation == "process.run"
    assert error.result.returncode != 0
    assert len(error.result.stdout) + len(error.result.stderr) == 1024
    assert (error.result.stdout if descriptor == 2 else error.result.stderr) == b""
    assert secret not in str(error)
    assert secret not in caplog.text
    (record,) = caplog.records
    assert record.outcome == "output_limit"
    assert record.returncode == error.result.returncode


def test_stdout_and_stderr_share_one_capture_budget(runner: ProcessRunner) -> None:
    script = "import os, time; os.write(1, b'o' * 768); os.write(2, b'e' * 768); time.sleep(30)"
    with pytest.raises(ProcessOutputLimit) as raised:
        runner.run([sys.executable, "-c", script], max_output_bytes=1024, check=False)
    result = raised.value.result
    assert len(result.stdout) + len(result.stderr) == 1024
    assert result.stdout and result.stderr
    assert set(result.stdout) == {ord("o")}
    assert set(result.stderr) == {ord("e")}


def test_output_at_the_combined_capture_limit_succeeds(runner: ProcessRunner) -> None:
    script = "import os; os.write(1, b'o' * 400); os.write(2, b'e' * 624)"
    result = runner.run([sys.executable, "-c", script], max_output_bytes=1024)
    assert result.returncode == 0
    assert result.stdout == b"o" * 400
    assert result.stderr == b"e" * 624


def test_exited_process_output_is_still_checked_against_the_limit(runner: ProcessRunner) -> None:
    script = "import os; os.write(1, b'x' * 1025)"
    with pytest.raises(ProcessOutputLimit) as raised:
        runner.run([sys.executable, "-c", script], max_output_bytes=1024)
    assert raised.value.result.stdout == b"x" * 1024
    assert raised.value.result.stderr == b""


@pytest.mark.parametrize("runner_seconds,call_seconds", [(1, None), (5, 1), (1, 5)])
def test_limited_capture_keeps_timeout_and_partial_output(
    runner_seconds: float, call_seconds: float | None
) -> None:
    runner = ProcessRunner([Path(sys.executable).name], timeout_seconds=runner_seconds)
    script = "import os, time; os.write(1, b'started'); os.write(2, b'waiting'); time.sleep(30)"
    with pytest.raises(ProcessTimeout) as raised:
        runner.run(
            [sys.executable, "-c", script],
            max_output_bytes=1024,
            timeout_seconds=call_seconds,
        )
    assert raised.value.stdout == b"started"
    assert raised.value.stderr == b"waiting"


def test_limited_capture_delivers_large_stdin_without_pipe_deadlock(runner: ProcessRunner) -> None:
    payload = bytes(range(256)) * 1024
    script = (
        "import hashlib, sys; data = sys.stdin.buffer.read(); "
        "sys.stdout.buffer.write(hashlib.sha256(data).digest()); "
        "sys.stderr.buffer.write(str(len(data)).encode())"
    )
    result = runner.run([sys.executable, "-c", script], stdin=payload, max_output_bytes=38)
    assert result.stdout == hashlib.sha256(payload).digest()
    assert result.stderr == str(len(payload)).encode()


def test_limited_capture_retains_nonzero_exit_semantics(runner: ProcessRunner) -> None:
    script = "import sys; sys.stderr.write('specific failure'); raise SystemExit(3)"
    with pytest.raises(ProcessError) as raised:
        runner.run([sys.executable, "-c", script], max_output_bytes=1024)
    assert raised.value.result.returncode == 3
    assert raised.value.result.stderr == b"specific failure"
    result = runner.run([sys.executable, "-c", script], max_output_bytes=1024, check=False)
    assert result.returncode == 3
    assert result.stderr == b"specific failure"


def test_limited_capture_retains_environment_and_correlation_controls(
    runner: ProcessRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "parent-only-token")
    script = (
        "import os, sys; "
        "assert 'GITHUB_TOKEN' not in os.environ; "
        "assert os.environ['EXPLICIT'] == 'provided'; "
        "sys.stdout.write(os.environ['TRAUST_REQUEST_ID'])"
    )
    with correlation_scope("limited-run"):
        result = runner.run(
            [sys.executable, "-c", script],
            env={"EXPLICIT": "provided", "TRAUST_REQUEST_ID": "spoofed"},
            max_output_bytes=64,
        )
    assert result.stdout == b"limited-run"


def test_limited_capture_cannot_bypass_the_allowlist() -> None:
    with pytest.raises(ValidationError):
        ProcessRunner([]).run([sys.executable, "-c", "pass"], max_output_bytes=1024)


@pytest.mark.parametrize("limit", [0, -1, True])
def test_capture_limit_must_be_a_positive_integer(runner: ProcessRunner, limit: int) -> None:
    with pytest.raises(ValidationError):
        runner.run([sys.executable, "-c", "pass"], max_output_bytes=limit)
