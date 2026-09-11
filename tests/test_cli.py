import json
import subprocess
from typing import Any

import pytest
from typer.testing import CliRunner

from keyvault.cli import app

runner = CliRunner()


def bw_stub(**responses: str) -> Any:
    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 0, responses.get(argv[1], ""), "")

    return run


def test_unlock_emits_a_quotable_export(monkeypatch: pytest.MonkeyPatch) -> None:
    # Session keys are base64 and can contain characters a shell would split
    # on, so the value has to survive eval intact.
    monkeypatch.setenv("BW_SESSION", "ab+/cd==  x")
    monkeypatch.setattr(
        subprocess, "run", bw_stub(status=json.dumps({"status": "unlocked"}))
    )
    result = runner.invoke(app, ["unlock"])
    assert result.exit_code == 0
    assert result.stdout.strip() == "export BW_SESSION='ab+/cd==  x'"


def test_lock_invalidates_the_session_and_clears_the_variable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(subprocess, "run", run)
    result = runner.invoke(app, ["lock"])
    assert result.exit_code == 0
    assert calls == [["bw", "lock"]]
    assert result.stdout.strip() == "unset BW_SESSION"


def test_expected_failures_are_a_message_not_a_traceback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("BW_SESSION", raising=False)
    monkeypatch.setattr(
        subprocess, "run", bw_stub(status=json.dumps({"status": "unauthenticated"}))
    )
    result = runner.invoke(app, ["dump"])
    assert result.exit_code != 0
    assert "bw login" in str(result.exception)
    assert not isinstance(result.exception, AttributeError | KeyError | TypeError)


def test_changes_reports_paths_and_never_values() -> None:
    from keyvault.cli import _changes

    removed, added, changed = _changes(
        {"ssh.a": "keep", "ssh.b": "old", "env.X": "gone"},
        {"ssh.a": "keep", "ssh.b": "new", "env.Y": "fresh"},
    )
    assert removed == ["env.X"]
    assert added == ["env.Y"]
    assert changed == ["ssh.b"]
    assert not {"old", "new", "gone", "fresh"} & set(removed + added + changed)


def test_secrets_store_reads_stdin_and_never_takes_a_value_in_argv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import base64

    item = {"id": "i1", "name": "keyvault", "revisionDate": "r1", "fields": []}
    sent: list[dict[str, Any]] = []

    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        sent.append({"argv": argv, **kwargs})
        out = {
            "status": json.dumps({"status": "unlocked"}),
            "list": json.dumps([item]),
        }.get(argv[1], "")
        return subprocess.CompletedProcess(argv, 0, out, "")

    monkeypatch.setenv("BW_SESSION", "s")
    monkeypatch.setattr(subprocess, "run", run)

    result = runner.invoke(
        app, ["secrets", "store", "GEMINI_API_KEY", "--stdin"], input="sk-secret\n"
    )
    assert result.exit_code == 0, result.output
    edit = next(c for c in sent if c["argv"][1] == "edit")
    assert "sk-secret" not in " ".join(edit["argv"])
    fields = json.loads(base64.b64decode(edit["input"]))["fields"]
    assert {"name": "env.GEMINI_API_KEY", "value": "sk-secret", "type": 1} in fields
