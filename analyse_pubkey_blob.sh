#!/bin/bash
# analyse_pubkey_blob.sh
# Usage: ./analyse_pubkey_blob.sh <hex_dump.txt>
# Analyze the structure of the SSH string sent as a public key blob (hex)

set -e

if [ $# -ne 1 ]; then
  echo "Usage: $0 <hex_dump.txt>" >&2
  exit 1
fi

HEX=$(cat "$1" | tr -d '\n ')

# Read SSH string length (first 4 bytes)
LEN_HEX=${HEX:0:8}
LEN=$((16#$LEN_HEX))
BLOB=${HEX:8:$((LEN*2))}

# Display size and start/end of blob
echo "SSH string length: $LEN ($LEN_HEX)"
echo "First 32 bytes: ${BLOB:0:64}"
echo "Last 32 bytes:  ${BLOB: -64}"
echo "Total blob hex: $BLOB"

# Check that the blob length is plausible for an OpenSSH Ed25519 certificate
if [ $LEN -lt 400 ] || [ $LEN -gt 1024 ]; then
  echo "[WARN] Blob length does not match a standard OpenSSH Ed25519 certificate."
else
  echo "[OK] Length plausible for an Ed25519 certificate."
fi
