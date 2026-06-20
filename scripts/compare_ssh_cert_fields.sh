#!/bin/bash
# compare_ssh_cert_fields.sh
# Usage: ./scripts/compare_ssh_cert_fields.sh ref_ed25519-cert.pub cert_swift.bin
# Compare field-by-field the extracted dumps from two certificates (OpenSSH .pub and Swift binary)

set -e

if [ $# -ne 2 ]; then
  echo "Usage: $0 <ref_ed25519-cert.pub> <cert_swift.bin>" >&2
  exit 1
fi

REF_PUB="$1"
SWIFT_BIN="$2"

# Extract fields
./scripts/extract_ssh_cert_fields.sh "$REF_PUB" > ref_fields.txt
./scripts/extract_ssh_cert_fields_bin.sh "$SWIFT_BIN" > swift_fields.txt

# List of fields to compare (must match extraction labels)
FIELDS=(keytype nonce publicKey serial certType keyId validPrincipals validAfter validBefore criticalOptions extensions reserved signatureKey signature)

DIFF_FOUND=0
for field in "${FIELDS[@]}"; do
  ref_val=$(grep "^$field:" ref_fields.txt | head -1 | cut -d: -f2- | xargs)
  swift_val=$(grep "^$field:" swift_fields.txt | head -1 | cut -d: -f2- | xargs)
  if [ "$ref_val" != "$swift_val" ]; then
    echo "[DIFF] $field:" >&2
    echo "  OpenSSH: $ref_val" >&2
    echo "  Swift:   $swift_val" >&2
    DIFF_FOUND=1
  fi
done

# Report results
if [ $DIFF_FOUND -eq 0 ]; then
  echo "All main fields are identical!"
else
  echo "Differences were detected. See above."
fi

# Cleanup
test -f ref_fields.txt && rm ref_fields.txt
test -f swift_fields.txt && rm swift_fields.txt
