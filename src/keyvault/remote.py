"""Reading and writing a remote authorized_keys file.

Two properties this file exists to get right, both learned the hard way from
rsync.net, whose restricted shell is the least forgiving host here.

**Everything runs over one held-open connection.** sshd checks authorized_keys
once, at connection setup, so an established session survives the file changing
underneath it. A rollback issued on a *new* connection would fail in exactly
the case it is needed -- when the file just locked you out. So a ControlMaster
is opened first and every operation, including the rollback, goes through it.

**Only exit 255 means "could not authenticate".** ssh reserves 255 for its own
connection and auth failures and passes the remote command's status through
otherwise. Treating any non-zero exit as a lockout would roll back every
deploy on rsync.net, where `true` is not even a valid command.
"""

import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .errors import KeyvaultError

AUTHORIZED_KEYS = ".ssh/authorized_keys"
PREVIOUS = f"{AUTHORIZED_KEYS}.prev"

# ssh's own failure code, distinct from any status a remote command returns.
SSH_FAILURE = 255

_BASE_OPTIONS = ("-o", "BatchMode=yes", "-o", "ConnectTimeout=10")


class Session:
    """An open, already-authenticated connection to one host."""

    def __init__(self, target: str, socket: Path) -> None:
        self.target = target
        self._options = (*_BASE_OPTIONS, "-o", f"ControlPath={socket}")

    def read_authorized_keys(self) -> str:
        """The host's authorized_keys, or "" if it has none yet."""
        with tempfile.TemporaryDirectory() as directory:
            local = Path(directory) / "authorized_keys"
            if self._scp(f"{self.target}:{AUTHORIZED_KEYS}", str(local)).returncode:
                return ""
            return local.read_text()

    def write_authorized_keys(self, text: str) -> None:
        """Replace authorized_keys, keeping the previous copy as .prev."""
        # No .prev on a host that had no authorized_keys; not an error.
        self._ssh("cp", AUTHORIZED_KEYS, PREVIOUS)
        with tempfile.TemporaryDirectory() as directory:
            local = Path(directory) / "authorized_keys"
            local.write_text(text)
            local.chmod(0o600)
            if self._scp(str(local), f"{self.target}:{AUTHORIZED_KEYS}").returncode:
                raise KeyvaultError(
                    f"could not upload authorized_keys to {self.target}"
                )
        # Explicit, not relying on scp to carry the mode: macOS ships a newer
        # OpenSSH whose scp uses the SFTP backend, where that is not assured.
        if self._ssh("chmod", "600", AUTHORIZED_KEYS).returncode:
            raise KeyvaultError("uploaded authorized_keys but could not chmod it")

    def restore_previous(self) -> bool:
        """Put .prev back. Runs over this session, so a lockout cannot block it."""
        return self._ssh("mv", PREVIOUS, AUTHORIZED_KEYS).returncode == 0

    def strict_mode_problems(self) -> list[str]:
        """Paths sshd's StrictModes would reject.

        Group- or other-writable home, ~/.ssh or authorized_keys all make sshd
        ignore the file, which is indistinguishable from a rejected key. Reads
        the POSIX permission string from `ls` rather than using `stat`, whose
        flags differ between BSD and GNU.
        """
        problems = []
        for label, args in (
            ("~", ("ls", "-ld", ".")),
            ("~/.ssh", ("ls", "-ld", ".ssh")),
            (f"~/{AUTHORIZED_KEYS}", ("ls", "-l", AUTHORIZED_KEYS)),
        ):
            proc = self._ssh(*args)
            if proc.returncode or not proc.stdout.strip():
                continue
            mode = proc.stdout.split()[0]
            if len(mode) >= 10 and (mode[5] == "w" or mode[8] == "w"):
                problems.append(f"{label} is {mode} -- group or other writable")
        return problems

    def _ssh(self, *args: str) -> subprocess.CompletedProcess[str]:
        return _run(["ssh", *self._options, self.target, *args])

    def _scp(self, source: str, destination: str) -> subprocess.CompletedProcess[str]:
        return _run(["scp", "-q", *self._options, source, destination])


@contextmanager
def connect(target: str) -> Iterator[Session]:
    """Hold one authenticated connection open for the life of the block."""
    with tempfile.TemporaryDirectory(prefix="kv-") as directory:
        # Short path: a Unix socket cannot exceed ~104 characters.
        socket = Path(directory) / "s"
        opened = _run(
            ["ssh", "-M", "-S", str(socket), *_BASE_OPTIONS, "-N", "-f", target]
        )
        if opened.returncode:
            raise KeyvaultError(f"cannot reach {target}: {opened.stderr.strip()}")
        try:
            yield Session(target, socket)
        finally:
            _run(["ssh", "-S", str(socket), "-O", "exit", target])


def can_authenticate(target: str) -> bool:
    """Whether a brand-new connection authenticates.

    Deliberately bypasses any ControlMaster: reusing the held-open session
    would prove nothing about the file just written. `ls` rather than `true`
    because restricted shells may not have `true`, and only 255 is read as an
    authentication failure.
    """
    proc = _run(["ssh", "-o", "ControlPath=none", *_BASE_OPTIONS, target, "ls"])
    return proc.returncode != SSH_FAILURE


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, check=False)
