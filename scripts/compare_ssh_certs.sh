#!/usr/bin/env sh
# Tools/compare_ssh_certs.sh
# Usage: ./scripts/compare_ssh_certs.sh our_cert.bin ref_cert.bin|ref_cert.pub
# Parse both certificates (binary or OpenSSH .pub) and show field-by-field differences

set -euo pipefail

if [ "$#" -ne 2 ]; then
  printf "Usage: %s <our_cert.bin> <ref_cert.bin|ref_cert.pub>\n" "$0" >&2
  exit 2
fi

OUR="$1"
REF="$2"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

# detect if file is an OpenSSH .pub line (text with two or three fields)
is_pub() {
  if [ -f "$1" ] && awk 'NF>=2 {exit 0} END{exit 1}' "$1" >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

if is_pub "$REF"; then
  ./extract_ssh_cert_fields.sh "$REF" > "$TMPDIR/ref.parsed"
else
  ./extract_ssh_cert_fields_bin.sh "$REF" > "$TMPDIR/ref.parsed"
fi

# Our cert is expected to be a binary cert blob
./extract_ssh_cert_fields_bin.sh "$OUR" > "$TMPDIR/our.parsed"

printf "=== Reference parsed (%s) ===\n" "$REF"
cat "$TMPDIR/ref.parsed"
printf "\n=== Our parsed (%s) ===\n" "$OUR"
cat "$TMPDIR/our.parsed"

# normalize to key=value lines for comparison
export LC_ALL=C
awk -F": " '{ print $1 "=" substr($0, index($0,$2)) }' "$TMPDIR/ref.parsed" > "$TMPDIR/ref.kv"
awk -F": " '{ print $1 "=" substr($0, index($0,$2)) }' "$TMPDIR/our.parsed" > "$TMPDIR/our.kv"

printf "\n=== Field differences ===\n"

# build union of keys
keys=$(cat "$TMPDIR/ref.kv" "$TMPDIR/our.kv" | cut -d'=' -f1 | sort -u)
# By default ignore fields that are expected to differ between independently-signed certs
IGNORED="nonce_hex serial keyId keyId_hex validPrincipals validPrincipals_hex validAfter validBefore signatureKey signatureKey_hex signature_hex"

for k in $keys; do
  case " $IGNORED " in *" $k "*) continue ;; esac
  ref_val=$(grep "^$k=" "$TMPDIR/ref.kv" 2>/dev/null | sed 's/^[^=]*=//') || ref_val=""
  our_val=$(grep "^$k=" "$TMPDIR/our.kv" 2>/dev/null | sed 's/^[^=]*=//') || our_val=""
  if [ "$ref_val" != "$our_val" ]; then
    if [ -z "$ref_val" ]; then
      printf "[ONLY IN OUR] %s\n  OUR: %s\n" "$k" "$our_val"
    elif [ -z "$our_val" ]; then
      printf "[ONLY IN REF] %s\n  REF: %s\n" "$k" "$ref_val"
    else
      printf "[DIFF] %s\n  REF: %s\n  OUR: %s\n" "$k" "$ref_val" "$our_val"
    fi
  fi
 done

exit 0
