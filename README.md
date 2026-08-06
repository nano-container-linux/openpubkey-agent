# OpenPubkeyAgent

Native macOS menu-bar agent for **OpenPubkey SSH certificates**: it logs
you in through an OIDC provider, issues short-lived SSH certificates, and
serves them from an in-memory SSH agent so you can SSH without a private
key on disk.

## Features

The agent is functional today (see [TESTING.md](TESTING.md) for the
end-to-end test against `opkssh`):

- **OIDC login** to obtain an identity token (`OIDCAuth`,
  `ProviderConfig`, `OIDCPasswordPrompt`).
- **OpenPubkey SSH certificate issuance** — generates an Ed25519 key and
  signs a certificate with the agent's CA (`SSHCA`, `SSHEd25519Cert`,
  `SSHKeygen`).
- **In-memory SSH agent** speaking the SSH agent protocol over a Unix
  socket at `/tmp/openpubkey-agent.sock` (`SSHAgent`,
  `SSHAgentProtocol`); certificates never touch disk.
- **Native macOS menu-bar UI** with a "Login & Load SSH Key" action and
  settings windows (`SettingsWindow`, `SettingsManagerWindow`).
- **`opkssh` integration** — `opkssh login --agent` uses the loaded
  certificate.

Automatic, unattended certificate renewal is the project's north star and
is being built on top of this foundation.

## Using the agent with OpenSSH

Point your SSH client at the agent socket:

```sh
export SSH_AUTH_SOCK=/tmp/openpubkey-agent.sock
```

Then, from the menu bar, click **Login & Load SSH Key**. Verify the
loaded certificate with:

```sh
ssh-add -l -E sha256   # shows the "OpenPubkey SSH Cert" identity
```

### Exporting the CA public key for OpenSSH

To let OpenSSH trust certificates issued by this agent, add the CA public
key to `~/.ssh/known_hosts` (or `authorized_keys`) as a
`@cert-authority` line.

1. Export the CA public key in OpenSSH format (shell only):

	```sh
	priv=$(cat "$HOME/.openpubkey-ca.key")
	pubhex=$(xxd -p -c 64 "$HOME/.openpubkey-ca.key" | cut -c 65-128)
	pubbin=$(echo "$pubhex" | xxd -r -p)
	keytype="ssh-ed25519"
	keytype_len=$(printf "%08x" ${#keytype})
	pubkey_len=$(printf "%08x" 32)
	blob=$(printf "%s" "$keytype_len" | xxd -r -p)
	blob+=$keytype
	blob+=$(printf "%s" "$pubkey_len" | xxd -r -p)
	blob+="$pubbin"
	b64=$(printf "%s" "$blob" | base64)
	echo "ssh-ed25519 $b64 openpubkey-ca"
	```

2. Add the output as a `@cert-authority` line, for example:

	```sh
	echo "@cert-authority * <output-from-above>" >> ~/.ssh/known_hosts
	```

## Project structure

| Path                        | Role                                              |
| --------------------------- | ------------------------------------------------- |
| `Sources/App/`              | Menu-bar application entry point.                 |
| `Sources/OpenPubkeyAgentLib/` | Core library: OIDC, SSH CA, SSH agent, UI windows. |
| `Tests/`                    | Unit tests + reference certificate fixtures.      |
| `Tools/CertGen/`            | Helper that generates test certificates.          |
| `Taskfile.yaml`             | Task automation.                                  |

## Build & test

A native Swift Package / Xcode project. Open the folder in Xcode, or use
the `Taskfile.yaml` targets. See [TESTING.md](TESTING.md) for the manual
and automated integration tests.

## License

BSD-3-Clause — see [LICENSE](LICENSE).
