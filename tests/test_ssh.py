import pathlib
import socket
from pathlib import Path

import pytest

from keyvault import ssh
from keyvault.errors import KeyvaultError


@pytest.fixture
def private(tmp_path: Path) -> str:
    return ssh.generate("test", tmp_path / "id_test")


def test_names_lists_only_ssh_entries() -> None:
    assert ssh.names({"ssh.laptop": "a", "ssh.desk": "b", "env.A": "1"}) == [
        "desk",
        "laptop",
    ]


def test_names_ignores_deeper_paths() -> None:
    # An older schema stored ssh.<name>.private/.public. Treating those as key
    # names fed a public key to ssh-keygen -y and failed in libcrypto.
    assert ssh.names({"ssh.oxygen.private": "a", "ssh.oxygen.public": "b"}) == []
    assert ssh.names({"ssh.oxygen": "a", "ssh.oxygen.private": "b"}) == ["oxygen"]


def test_private_key_names_the_missing_entry() -> None:
    with pytest.raises(KeyvaultError, match="no key named 'desk'"):
        ssh.private_key({"ssh.laptop": "a"}, "desk")


def test_default_name_rejects_a_hostname_that_is_not_a_path_segment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(socket, "gethostname", lambda: "host!name")
    with pytest.raises(KeyvaultError, match="pass one explicitly"):
        ssh.default_name()


def test_default_name_takes_the_short_hostname(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "gethostname", lambda: "Someones-MacBook-Pro.local")
    assert ssh.default_name() == "someones-macbook-pro"


def test_derived_public_key_matches_the_generated_pub_file(tmp_path: Path) -> None:
    # The whole schema rests on this: if derivation did not reproduce the real
    # public key, storing only the private half would be wrong.
    private = ssh.generate("test", tmp_path / "id_test")
    on_disk = (tmp_path / "id_test.pub").read_text().split()
    derived = ssh.public_key(private).split()
    assert derived[:2] == on_disk[:2]


def test_fingerprint_of_a_private_key(private: str) -> None:
    assert ssh.fingerprint(private).endswith("(ED25519)")


def test_generate_refuses_to_clobber(tmp_path: Path) -> None:
    ssh.generate("test", tmp_path / "id_test")
    with pytest.raises(KeyvaultError, match="already exists"):
        ssh.generate("test", tmp_path / "id_test")


def test_find_duplicate_matches_material_not_name(tmp_path: Path) -> None:
    one = ssh.generate("one", tmp_path / "id_one")
    two = ssh.generate("two", tmp_path / "id_two")
    fields = {"ssh.laptop": one}
    assert ssh.find_duplicate(fields, one, ignore="") == "laptop"
    assert ssh.find_duplicate(fields, two, ignore="") is None
    assert ssh.find_duplicate(fields, one, ignore="laptop") is None


def test_read_key_rejects_a_public_key(tmp_path: Path) -> None:
    # Pointing at the .pub by mistake would otherwise store a public key as if
    # it were private, and only fail much later at load time.
    ssh.generate("test", tmp_path / "id_test")
    with pytest.raises(KeyvaultError, match="not a private key"):
        ssh.read_key(tmp_path / "id_test.pub")


def test_read_key_reports_a_missing_file(tmp_path: Path) -> None:
    with pytest.raises(KeyvaultError, match="does not exist"):
        ssh.read_key(tmp_path / "nope")


def test_write_lays_out_both_halves_with_safe_permissions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, private: str
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    path = ssh.write("laptop", private, force=False)
    assert path == tmp_path / ".ssh" / "id_laptop"
    assert path.stat().st_mode & 0o777 == 0o600
    public_path = Path(f"{path}.pub")
    assert public_path.read_text().strip() == ssh.public_key(private)
    assert public_path.stat().st_mode & 0o777 == 0o644


def test_write_refuses_to_overwrite_without_force(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, private: str
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    ssh.write("laptop", private, force=False)
    with pytest.raises(KeyvaultError, match="--force"):
        ssh.write("laptop", private, force=False)
    assert ssh.write("laptop", private, force=True).exists()


def test_add_to_agent_without_an_agent_says_so(
    monkeypatch: pytest.MonkeyPatch, private: str
) -> None:
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
    with pytest.raises(KeyvaultError, match="SSH_AUTH_SOCK"):
        ssh.add_to_agent(private)


def test_public_key_leaves_no_file_behind(private: str) -> None:
    # It has to go through a file: ssh-keygen rejects a private key from a pipe
    # on macOS, where /dev/stdin is 0660. Nothing may survive the call.
    import tempfile

    before = set(pathlib.Path(tempfile.gettempdir()).iterdir())
    ssh.public_key(private)
    assert set(pathlib.Path(tempfile.gettempdir()).iterdir()) == before


def test_read_key_repairs_crlf_and_a_missing_final_newline(tmp_path: Path) -> None:
    # Exactly what a key pasted out of a Bitwarden note looks like. ssh-keygen
    # rejects both, so read_key has to fix them before storing.
    good = ssh.generate("src", tmp_path / "id_src")
    mangled = tmp_path / "pasted"
    mangled.write_text(good.replace("\n", "\r\n").rstrip("\r\n"))
    repaired = ssh.read_key(mangled)
    assert "\r" not in repaired
    assert repaired.endswith("\n")
    assert ssh.public_key(repaired) == ssh.public_key(good)


def test_read_key_rejects_a_truncated_key(tmp_path: Path) -> None:
    # Has the armor header, so a header check alone would accept it; only
    # actually parsing the key catches it.
    good = ssh.generate("src", tmp_path / "id_src")
    truncated = tmp_path / "half"
    truncated.write_text(good[: len(good) // 2] + "\n")
    with pytest.raises(KeyvaultError):
        ssh.read_key(truncated)


ED = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample"


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        (f"{ED} someone@host", ED),
        (ED, ED),
        # An options prefix must not be mistaken for the key type.
        (f'restrict,from="10.0.0.0/8" {ED} ci', ED),
        (f'command="/usr/bin/true",no-pty {ED}', ED),
        ("# just a comment", None),
        ("", None),
        ("ssh-ed25519", None),
        ("garbage line here", None),
    ],
)
def test_key_material_ignores_options_and_comments(
    line: str, expected: str | None
) -> None:
    assert ssh.key_material(line) == expected


def test_classify_names_known_keys_and_keeps_unknown_ones() -> None:
    other = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOther"
    text = "\n".join(
        [
            "# a comment",
            "",
            f"{ED} keyvault:oxygen",
            f"{other} deploy@ci",
        ]
    )
    assert ssh.classify(text, {"oxygen": ED}) == [
        ("oxygen", f"{ED} keyvault:oxygen"),
        (None, f"{other} deploy@ci"),
    ]


def test_classify_matches_material_not_comment() -> None:
    # Same key, different comment on the host: still recognised as ours.
    assert ssh.classify(f"{ED} whatever-else", {"oxygen": ED}) == [
        ("oxygen", f"{ED} whatever-else")
    ]


def test_authorized_line_is_labelled_with_the_vault_name(private: str) -> None:
    line = ssh.authorized_line("laptop", private)
    assert line.endswith(" keyvault:laptop")
    assert ssh.key_material(line) == ssh.key_material(ssh.public_key(private))
