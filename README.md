## Exporting the CA public key for OpenSSH

To allow OpenSSH to trust certificates issued by this agent, you must add the CA public key to your `~/.ssh/known_hosts` or `~/.ssh/authorized_keys` as a `@cert-authority` line.


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

2. Add the output to your `~/.ssh/known_hosts` or `~/.ssh/authorized_keys` as a `@cert-authority` line. For example:

	```sh
	echo "@cert-authority * <output-from-above>" >> ~/.ssh/known_hosts
	```

This will allow OpenSSH to recognize and trust certificates signed by your OpenPubkey agent's CA.
# OpenPubkeyAgent

macOS Swift application for automatic renewal of OpenPubkey SSH certificates.

## Planned Features
- Monitoring and automatic renewal of OpenPubkey SSH certificates
- Native macOS user interface
- Integration with Keychain and SSH agent

## Project Structure
- Sources/: Swift source code
- Taskfile.yaml: task automation

## Installation
Native Xcode project. Open the folder in Xcode to start development.
