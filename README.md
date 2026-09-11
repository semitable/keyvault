# keyvault

Bitwarden-backed management of the things a password manager stores well and
handles badly: SSH keys, a GPG key, and environment secrets.

One vault item, one schema rule, one entry point.

```sh
uv tool install git+https://github.com/USER/keyvault

keyvault ssh new                 # generate a key here, store it in the vault
keyvault ssh load laptop         # vault -> ssh-agent, nothing on disk
keyvault secrets show            # export lines for eval or redirection
keyvault gpg install             # vault -> local keyring
keyvault --help                  # everything else
```

Status: **early, in development.** See [docs/design.md](docs/design.md) for the
design and the reasoning behind it.

## Why

Keeping keys in a password manager means one item per secret, each needing a
name, with something in between translating names to variables and file paths.
Items accumulate and get orphaned. SSH keys are worse: a new machine gets a
fresh key, enrolled by hand wherever you remember, recorded nowhere -- so after
a few years you have keys you cannot account for on hosts you cannot audit.

`keyvault` keeps all of it in a single vault item under a dotted-path schema,
and makes enrolment an interactive operation against the host's real
`authorized_keys` rather than a map that drifts out of date.

## Requires

- Python 3.12+
- the [Bitwarden CLI](https://bitwarden.com/help/cli/) (`bw`), logged in

## Configuration

    KEYVAULT_ITEM   name of the Bitwarden item to use (default: keyvault)
