#!/usr/bin/env bash
set -euo pipefail
# Repo root assumed two levels up from Tools
REPO_DIR=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
USERKEY="$TMP/user"

echo "GENERATE: ssh-keygen"
/usr/bin/ssh-keygen -t ed25519 -f "$USERKEY" -N "" >/dev/null 2>&1

echo "CERTGEN: running certgen in repo"
cd "$REPO_DIR"
swift run certgen >/dev/null 2>&1

cp "$REPO_DIR/tmp/our-cert.bin" "$TMP/our-cert.bin"

CERTB64=$(base64 < "$TMP/our-cert.bin" | tr -d '\n')
echo "ssh-ed25519-cert-v01@openssh.com $CERTB64 test-cert" > "$TMP/user-cert.pub"

echo "RUN: ssh-keygen -Lf"
/usr/bin/ssh-keygen -Lf "$TMP/user-cert.pub"

echo "START: ssh-agent"
SSH_AGENT_OUT=$(ssh-agent -s)
echo "$SSH_AGENT_OUT"
SSH_AUTH_SOCK=$(echo "$SSH_AGENT_OUT" | sed -n 's/.*SSH_AUTH_SOCK=\([^;]*\);.*/\1/p')
SSH_AGENT_PID=$(echo "$SSH_AGENT_OUT" | sed -n 's/.*SSH_AGENT_PID=\([^;]*\);.*/\1/p')
export SSH_AUTH_SOCK SSH_AGENT_PID

echo "ADD: ssh-add"
ssh-add "$USERKEY" >/dev/null 2>&1 || true

echo "LIST: ssh-add -L"
ssh-add -L

kill -TERM "$SSH_AGENT_PID" >/dev/null 2>&1 || true
echo done
