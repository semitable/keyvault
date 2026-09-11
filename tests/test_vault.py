import json
import subprocess
from typing import Any

import pytest

from keyvault.errors import VaultError
from keyvault.vault import Vault

ITEM_ID = "0123abcd"


def item(fields: list[dict[str, Any]], revision: str = "r1") -> dict[str, Any]:
    return {
        "id": ITEM_ID,
        "name": "keyvault",
        "revisionDate": revision,
        "fields": fields,
    }


class FakeBw:
    """Stands in for the bw CLI, recording how it was invoked.

    subprocess is the right seam: bw is an external program, and the calls we
    most need to pin down are which arguments it receives and what reaches it
    on stdin.
    """

    def __init__(self, **responses: Any) -> None:
        self.responses = responses
        self.calls: list[dict[str, Any]] = []

    def __call__(
        self, argv: list[str], **kwargs: Any
    ) -> subprocess.CompletedProcess[str]:
        assert argv[0] == "bw"
        subcommand = argv[1]
        self.calls.append({"argv": argv, **kwargs})
        response = self.responses.get(subcommand, "")
        if isinstance(response, Exception):
            return subprocess.CompletedProcess(argv, 1, "", str(response))
        if callable(response):
            response = response(self)
        return subprocess.CompletedProcess(argv, 0, response, "")


@pytest.fixture
def unlocked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BW_SESSION", "s3ss10n")
    monkeypatch.delenv("KEYVAULT_ITEM", raising=False)


def install(monkeypatch: pytest.MonkeyPatch, fake: FakeBw) -> FakeBw:
    monkeypatch.setattr(subprocess, "run", fake)
    return fake


def test_unauthenticated_names_the_fix(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, FakeBw(status=json.dumps({"status": "unauthenticated"})))
    with pytest.raises(VaultError, match="bw login"):
        Vault()


def test_unexpected_status_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, FakeBw(status=json.dumps({"status": "banana"})))
    with pytest.raises(VaultError, match="banana"):
        Vault()


def test_session_never_appears_in_argv(
    monkeypatch: pytest.MonkeyPatch, unlocked: None
) -> None:
    fake = install(
        monkeypatch,
        FakeBw(
            status=json.dumps({"status": "unlocked"}),
            list=json.dumps([item([{"name": "env.A", "value": "1", "type": 1}])]),
        ),
    )
    Vault().read_fields()
    assert fake.calls
    for call in fake.calls:
        assert "s3ss10n" not in " ".join(call["argv"])
    envs = [c["env"] for c in fake.calls if c.get("env")]
    assert envs and all(e["BW_SESSION"] == "s3ss10n" for e in envs)


def test_read_returns_flat_fields(
    monkeypatch: pytest.MonkeyPatch, unlocked: None
) -> None:
    install(
        monkeypatch,
        FakeBw(
            status=json.dumps({"status": "unlocked"}),
            list=json.dumps(
                [
                    item(
                        [
                            {"name": "env.A", "value": "1", "type": 1},
                            {"name": "ssh.laptop.public", "value": "P", "type": 1},
                        ]
                    )
                ]
            ),
        ),
    )
    assert Vault().read_fields() == {"env.A": "1", "ssh.laptop.public": "P"}


def test_read_tolerates_an_item_with_no_fields(
    monkeypatch: pytest.MonkeyPatch, unlocked: None
) -> None:
    install(
        monkeypatch,
        FakeBw(
            status=json.dumps({"status": "unlocked"}),
            list=json.dumps([item([]) | {"fields": None}]),
        ),
    )
    assert Vault().read_fields() == {}


@pytest.mark.parametrize(
    ("found", "message"),
    [
        ([], "no vault item"),
        ([item([]), item([])], "2 vault items"),
    ],
)
def test_item_must_resolve_to_exactly_one(
    monkeypatch: pytest.MonkeyPatch,
    unlocked: None,
    found: list[dict[str, Any]],
    message: str,
) -> None:
    install(
        monkeypatch,
        FakeBw(status=json.dumps({"status": "unlocked"}), list=json.dumps(found)),
    )
    with pytest.raises(VaultError, match=message):
        Vault().read_fields()


def test_sync_failure_does_not_stop_a_read(
    monkeypatch: pytest.MonkeyPatch, unlocked: None, caplog: pytest.LogCaptureFixture
) -> None:
    install(
        monkeypatch,
        FakeBw(
            status=json.dumps({"status": "unlocked"}),
            sync=RuntimeError("offline"),
            list=json.dumps([item([{"name": "env.A", "value": "1", "type": 1}])]),
        ),
    )
    vault = Vault()
    vault.sync()
    assert "using the local cache" in caplog.text
    assert vault.read_fields() == {"env.A": "1"}


def test_write_refuses_when_the_item_changed(
    monkeypatch: pytest.MonkeyPatch, unlocked: None
) -> None:
    revisions = iter(["r1", "r2"])

    install(
        monkeypatch,
        FakeBw(
            status=json.dumps({"status": "unlocked"}),
            list=lambda _: json.dumps([item([], revision=next(revisions))]),
        ),
    )
    vault = Vault()
    vault.read_fields()
    with pytest.raises(VaultError, match="changed in the vault"):
        vault.write_fields({"env.A": "1"})


def test_write_sends_the_payload_on_stdin_and_keeps_field_types(
    monkeypatch: pytest.MonkeyPatch, unlocked: None
) -> None:
    import base64

    stored = [{"name": "env.A", "value": "old", "type": 0}]
    fake = install(
        monkeypatch,
        FakeBw(
            status=json.dumps({"status": "unlocked"}),
            list=json.dumps([item(stored)]),
            edit="",
        ),
    )
    vault = Vault()
    vault.read_fields()
    vault.write_fields({"env.A": "new", "env.B": "fresh"})

    edit = next(c for c in fake.calls if c["argv"][1] == "edit")
    assert edit["argv"] == ["bw", "edit", "item", ITEM_ID]
    assert "new" not in " ".join(edit["argv"])
    sent = json.loads(base64.b64decode(edit["input"]))
    by_name = {f["name"]: f for f in sent["fields"]}
    assert by_name["env.A"] == {"name": "env.A", "value": "new", "type": 0}
    assert by_name["env.B"]["type"] == 1


def test_create_makes_a_secure_note_with_no_fields(
    monkeypatch: pytest.MonkeyPatch, unlocked: None
) -> None:
    import base64

    fake = install(
        monkeypatch,
        FakeBw(status=json.dumps({"status": "unlocked"}), list="[]", create=""),
    )
    Vault().create()

    created = next(c for c in fake.calls if c["argv"][1] == "create")
    assert created["argv"] == ["bw", "create", "item"]
    sent = json.loads(base64.b64decode(created["input"]))
    assert sent["type"] == 2
    assert sent["name"] == "keyvault"
    assert sent["fields"] == []


def test_create_refuses_to_make_a_duplicate(
    monkeypatch: pytest.MonkeyPatch, unlocked: None
) -> None:
    install(
        monkeypatch,
        FakeBw(
            status=json.dumps({"status": "unlocked"}),
            list=json.dumps([item([])]),
            create="",
        ),
    )
    with pytest.raises(VaultError, match="already exists"):
        Vault().create()


def test_write_requires_a_prior_read(
    monkeypatch: pytest.MonkeyPatch, unlocked: None
) -> None:
    install(
        monkeypatch,
        FakeBw(
            status=json.dumps({"status": "unlocked"}),
            list=json.dumps([item([])]),
        ),
    )
    with pytest.raises(AssertionError):
        Vault().write_fields({"env.A": "1"})
