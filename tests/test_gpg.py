import pytest

from keyvault import gpg
from keyvault.errors import KeyvaultError

ARMOR = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nabc\n-----END-----\n"
REVOCATION = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nabc\n-----END-----\n"


def test_names_groups_by_key() -> None:
    assert gpg.names(
        {
            "gpg.personal.private": ARMOR,
            "gpg.personal.revocation-cert": REVOCATION,
            "gpg.work.private": ARMOR,
            "ssh.laptop": "k",
        }
    ) == ["personal", "work"]


def test_resolve_uses_the_only_key_when_unnamed() -> None:
    assert gpg.resolve({"gpg.personal.private": ARMOR}, "") == "personal"


def test_resolve_requires_a_name_when_there_are_several() -> None:
    fields = {"gpg.personal.private": ARMOR, "gpg.work.private": ARMOR}
    with pytest.raises(KeyvaultError, match="personal, work"):
        gpg.resolve(fields, "")


def test_resolve_reports_an_empty_vault() -> None:
    with pytest.raises(KeyvaultError, match="no gpg keys"):
        gpg.resolve({}, "")


def test_private_key_accepts_a_private_block() -> None:
    assert gpg.private_key({"gpg.personal.private": ARMOR}, "personal") == ARMOR


def test_private_key_reports_a_missing_field() -> None:
    with pytest.raises(KeyvaultError, match=r"no gpg\.personal\.private"):
        gpg.private_key({}, "personal")


@pytest.mark.parametrize("value", [REVOCATION, "not armored at all"])
def test_private_key_refuses_anything_but_a_private_block(value: str) -> None:
    # A revocation certificate is an armored PUBLIC KEY BLOCK and lives in the
    # adjacent field, so this guard is what stops a swapped value being used.
    with pytest.raises(KeyvaultError, match="refusing to use it"):
        gpg.private_key({"gpg.personal.private": value}, "personal")


def test_fingerprint_is_read_off_a_real_key_without_importing(
    tmp_path: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess

    home = tmp_path
    monkeypatch.setenv("GNUPGHOME", str(home))
    subprocess.run(
        [
            "gpg",
            "--batch",
            "--passphrase",
            "",
            "--quick-generate-key",
            "kv-test <t@example.invalid>",
            "ed25519",
            "sign",
            "never",
        ],
        capture_output=True,
        check=True,
    )
    listing = subprocess.run(
        ["gpg", "--list-secret-keys", "--with-colons"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    expected = next(
        line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")
    )
    armored = subprocess.run(
        ["gpg", "--armor", "--export-secret-keys", expected],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert gpg.fingerprint(armored) == expected


def test_find_duplicate_matches_by_fingerprint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gpg, "fingerprint", lambda private: f"FPR-OF-{private}")
    fields = {"gpg.personal.private": ARMOR, "gpg.work.private": "OTHER"}
    assert gpg.find_duplicate(fields, f"FPR-OF-{ARMOR}", ignore="") == "personal"
    assert gpg.find_duplicate(fields, f"FPR-OF-{ARMOR}", ignore="personal") is None
    assert gpg.find_duplicate(fields, "FPR-OF-nothing", ignore="") is None


def test_export_secret_refuses_a_key_not_in_the_keyring(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gpg, "installed_fingerprints", lambda: {"AAAA"})
    with pytest.raises(KeyvaultError, match="not a secret key in this keyring"):
        gpg.export_secret("BBBB")


def test_revocation_certificate_is_read_when_gpg_kept_one(
    tmp_path: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    import pathlib

    home = pathlib.Path(str(tmp_path))
    monkeypatch.setenv("GNUPGHOME", str(home))
    assert gpg.revocation_certificate("ABCD") is None
    revocs = home / "openpgp-revocs.d"
    revocs.mkdir()
    (revocs / "ABCD.rev").write_text(REVOCATION)
    assert gpg.revocation_certificate("ABCD") == REVOCATION
