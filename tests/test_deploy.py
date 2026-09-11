import json
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
import questionary
from typer.testing import CliRunner

from keyvault import remote, ssh
from keyvault.cli import _choose, app
from keyvault.errors import KeyvaultError

runner = CliRunner()
TARGET = "user@host"
STRANGER = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIStranger deploy@ci"


class FakeSession:
    """A host whose authorized_keys lives in memory."""

    def __init__(self, contents: str = "", *, modes: list[str] | None = None) -> None:
        self.contents = contents
        self.previous: str | None = None
        self.modes = modes or []
        self.chmod_called = False

    def read_authorized_keys(self) -> str:
        return self.contents

    def write_authorized_keys(self, text: str) -> None:
        # A host with no authorized_keys yet has nothing to copy to .prev, so
        # there is nothing to roll back to -- as on a real host.
        self.previous = self.contents or None
        self.contents = text
        self.chmod_called = True

    def restore_previous(self) -> bool:
        if self.previous is None:
            return False
        self.contents, self.previous = self.previous, None
        return True

    def strict_mode_problems(self) -> list[str]:
        return self.modes


@pytest.fixture
def vault(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """An unlocked vault holding one real ssh key; bw never runs."""
    private = ssh.generate("oxygen", tmp_path / "id_oxygen")
    item = {
        "id": "i1",
        "name": "keyvault",
        "revisionDate": "r1",
        "fields": [{"name": "ssh.oxygen", "value": private, "type": 1}],
    }
    real_run = subprocess.run

    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if argv[0] != "bw":
            return real_run(argv, **kwargs)
        out = {
            "status": json.dumps({"status": "unlocked"}),
            "list": json.dumps([item]),
        }.get(argv[1], "")
        return subprocess.CompletedProcess(argv, 0, out, "")

    monkeypatch.setenv("BW_SESSION", "s")
    monkeypatch.setattr(subprocess, "run", run)


def use(
    monkeypatch: pytest.MonkeyPatch, session: FakeSession, *, authenticates: bool
) -> FakeSession:
    @contextmanager
    def connect(target: str) -> Any:
        yield session

    monkeypatch.setattr(remote, "connect", connect)
    monkeypatch.setattr(remote, "can_authenticate", lambda target: authenticates)
    return session


def test_without_apply_nothing_is_written(
    vault: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = use(monkeypatch, FakeSession(), authenticates=True)
    result = runner.invoke(app, ["ssh", "deploy", TARGET], input="y\n")
    assert result.exit_code == 0, result.output
    assert "would write" in result.output
    assert session.contents == ""


def test_refuses_to_authorise_nothing(
    vault: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = use(monkeypatch, FakeSession(), authenticates=True)
    result = runner.invoke(app, ["ssh", "deploy", TARGET, "--apply"], input="n\n")
    assert result.exit_code != 0
    assert "no keys at all" in str(result.exception)
    assert session.contents == ""


def test_bad_modes_stop_the_write(vault: None, monkeypatch: pytest.MonkeyPatch) -> None:
    session = use(
        monkeypatch,
        FakeSession(modes=["~/.ssh is drwxrwx--- -- group or other writable"]),
        authenticates=True,
    )
    result = runner.invoke(app, ["ssh", "deploy", TARGET, "--apply"], input="y\n")
    assert result.exit_code != 0
    assert "would ignore authorized_keys" in str(result.exception)
    assert session.contents == "", "must not write a file sshd would ignore"


def test_failed_verification_rolls_back(
    vault: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = use(monkeypatch, FakeSession(STRANGER + "\n"), authenticates=False)
    result = runner.invoke(app, ["ssh", "deploy", TARGET, "--apply"], input="y\ny\n")
    assert result.exit_code != 0
    assert "restored" in str(result.exception)
    assert session.contents == STRANGER + "\n", "the original must be back"


def test_rollback_failure_says_the_host_needs_fixing(
    vault: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    use(monkeypatch, FakeSession(), authenticates=False)
    # No prior authorized_keys, so there is no .prev to restore.
    result = runner.invoke(app, ["ssh", "deploy", TARGET, "--apply"], input="y\n")
    assert result.exit_code != 0
    assert "could not be restored" in str(result.exception)


def test_unknown_keys_are_kept_by_default(
    vault: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = use(monkeypatch, FakeSession(STRANGER + "\n"), authenticates=True)
    # y for our key; a bare newline accepts the default (keep) for the stranger.
    result = runner.invoke(app, ["ssh", "deploy", TARGET, "--apply"], input="y\n\n")
    assert result.exit_code == 0, result.output
    assert STRANGER in session.contents
    assert "keyvault:oxygen" in session.contents


def test_can_authenticate_treats_only_255_as_auth_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # rsync.net's restricted shell has no `true`, so a non-zero exit from the
    # probe command must not be read as a lockout. Only ssh's own 255 is.
    codes: list[int] = []

    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, codes.pop(0), "", "")

    monkeypatch.setattr(subprocess, "run", run)
    codes[:] = [1]
    assert remote.can_authenticate(TARGET) is True
    codes[:] = [0]
    assert remote.can_authenticate(TARGET) is True
    codes[:] = [255]
    assert remote.can_authenticate(TARGET) is False


def test_can_authenticate_bypasses_any_control_master(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Reusing the held-open session would prove nothing about the new file.
    seen: list[list[str]] = []

    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(subprocess, "run", run)
    remote.can_authenticate(TARGET)
    assert "ControlPath=none" in seen[0]


OPTIONS = [("line-a", "alpha", True), ("line-b", "bravo", False), ("line-c", "c", True)]


def test_choose_uses_a_checkbox_on_a_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    class FakeQuestion:
        def ask(self) -> list[str]:
            return ["line-c", "line-a"]

    def checkbox(title: str, choices: list[Any]) -> FakeQuestion:
        captured["checked"] = [c.checked for c in choices]
        return FakeQuestion()

    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(questionary, "checkbox", checkbox)
    monkeypatch.setattr(questionary, "Choice", _Choice)

    chosen = _choose("pick", OPTIONS)
    # Pre-ticked from the host's current state, and the file keeps the order
    # shown rather than the order the answer came back in.
    assert captured["checked"] == [True, False, True]
    assert chosen == ["line-a", "line-c"]


def test_choose_treats_cancellation_as_an_abort(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Cancelled:
        def ask(self) -> None:
            return None

    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(questionary, "checkbox", lambda *a, **k: Cancelled())
    monkeypatch.setattr(questionary, "Choice", _Choice)

    with pytest.raises(KeyvaultError, match="cancelled"):
        _choose("pick", OPTIONS)


class _Choice:
    def __init__(self, label: str, value: str, checked: bool) -> None:
        self.label, self.value, self.checked = label, value, checked
