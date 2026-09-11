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
