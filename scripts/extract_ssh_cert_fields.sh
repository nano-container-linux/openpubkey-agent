#!/bin/bash
# extract_ssh_cert_fields.sh
# Usage: ./scripts/extract_ssh_cert_fields.sh ref_ed25519-cert.pub
# Extracts and prints main fields (nonce, publicKey, serial, certType, keyId, validPrincipals, validAfter, validBefore, criticalOptions, extensions, reserved, signatureKey, signature) from an OpenSSH Ed25519 certificate (public key file)
# Requires: xxd, base64, awk, od, printf, bash >= 4

set -e
export LC_ALL=C

if [ $# -ne 1 ]; then
  echo "Usage: $0 <cert.pub>" >&2
  exit 1
fi

PUB="$1"
BLOB=$(awk '{print $2}' "$PUB")
CERTBIN=openssh_cert.bin

echo "$BLOB" | base64 -d > "$CERTBIN"

# Helper: read SSH string (4 bytes len + data)
read_ssh_string() {
  local file=$1; local offset=$2
  local len_hex=$(dd if="$file" bs=1 skip=$offset count=4 2>/dev/null | xxd -p)
  local len=$((16#$(echo $len_hex)))
  local data_offset=$((offset+4))
  local data=$(dd if="$file" bs=1 skip=$data_offset count=$len 2>/dev/null | xxd -p -c 1000)
  local next_offset=$((data_offset+len))
  echo "$data $next_offset $len"
}

# Helper: read uint64 big endian
dump_u64() {
  local file=$1; local offset=$2
  local val=$(dd if="$file" bs=1 skip=$offset count=8 2>/dev/null | od -An -t x8 | tr -d ' ')
  echo "$val"
}
# Helper: read uint32 big endian
dump_u32() {
  local file=$1; local offset=$2
  local val=$(dd if="$file" bs=1 skip=$offset count=4 2>/dev/null | od -An -t x4 | tr -d ' ')
  echo "$val"
}

# Start parsing
OFFSET=0
# keytype
read keytype_hex OFFSET LEN < <(read_ssh_string "$CERTBIN" $OFFSET)
keytype_ascii=$(echo "$keytype_hex" | xxd -r -p 2>/dev/null | sed 's/[^[:print:]]/./g')
echo "keytype: $keytype_ascii"
echo "keytype_hex: $keytype_hex"
# nonce
read nonce_hex OFFSET LEN < <(read_ssh_string "$CERTBIN" $OFFSET)
echo "nonce_hex:   $nonce_hex"
# publicKey field ([string][string])
read pubkeyfield_hex OFFSET LEN < <(read_ssh_string "$CERTBIN" $OFFSET)
# parse pubkeyfield
PUBKEYFIELD_BIN=pubkeyfield.bin
echo $pubkeyfield_hex | xxd -r -p > $PUBKEYFIELD_BIN
PUBKEY_OFFSET=0
read pubkeytype_hex PUBKEY_OFFSET LEN < <(read_ssh_string $PUBKEYFIELD_BIN $PUBKEY_OFFSET)
read pubkey_hex PUBKEY_OFFSET LEN < <(read_ssh_string $PUBKEYFIELD_BIN $PUBKEY_OFFSET)
echo "publicKey_hex: $pubkey_hex"
pubkey_ascii=$(echo "$pubkey_hex" | xxd -r -p 2>/dev/null | sed 's/[^[:print:]]/./g')
echo "publicKey: $pubkey_ascii"
# serial
serial=$(dump_u64 "$CERTBIN" $OFFSET)
OFFSET=$((OFFSET+8))
echo "serial:  $serial"
# certType
certType=$(dump_u32 "$CERTBIN" $OFFSET)
OFFSET=$((OFFSET+4))
echo "certType: $certType"
# keyId
read keyid_hex OFFSET LEN < <(read_ssh_string "$CERTBIN" $OFFSET)
keyid_ascii=$(echo "$keyid_hex" | xxd -r -p 2>/dev/null | sed 's/[^[:print:]]/./g')
echo "keyId:   $keyid_ascii"
echo "keyId_hex: $keyid_hex"
# validPrincipals
read principals_hex OFFSET LEN < <(read_ssh_string "$CERTBIN" $OFFSET)
echo "validPrincipals_hex: $principals_hex"
principals_ascii=$(echo "$principals_hex" | xxd -r -p 2>/dev/null | sed 's/[^[:print:]]/./g')
echo "validPrincipals: $principals_ascii"
# validAfter
validAfter=$(dump_u64 "$CERTBIN" $OFFSET)
OFFSET=$((OFFSET+8))
echo "validAfter:  $validAfter"
# validBefore
validBefore=$(dump_u64 "$CERTBIN" $OFFSET)
OFFSET=$((OFFSET+8))
echo "validBefore: $validBefore"
# criticalOptions
# criticalOptions
read critopt_hex OFFSET LEN < <(read_ssh_string "$CERTBIN" $OFFSET)
echo "criticalOptions_hex: $critopt_hex"
# extensions
# extensions
read ext_hex OFFSET LEN < <(read_ssh_string "$CERTBIN" $OFFSET)
echo "extensions_hex: $ext_hex"
ext_ascii=$(echo "$ext_hex" | xxd -r -p 2>/dev/null | sed 's/[^[:print:]]/./g')
echo "extensions: $ext_ascii"
# reserved (4 raw bytes, not an ssh-string)
reserved_hex=$(dd if="$CERTBIN" bs=1 skip=$OFFSET count=4 2>/dev/null | xxd -p -c 1000)
OFFSET=$((OFFSET+4))
echo "reserved_hex: $reserved_hex"
# signatureKey ([string][string])
read sigkeyfield_hex OFFSET LEN < <(read_ssh_string "$CERTBIN" $OFFSET)
echo $sigkeyfield_hex | xxd -r -p > sigkeyfield.bin
SIGKEY_OFFSET=0
read sigkeytype_hex SIGKEY_OFFSET LEN < <(read_ssh_string sigkeyfield.bin $SIGKEY_OFFSET)
read sigkey_hex SIGKEY_OFFSET LEN < <(read_ssh_string sigkeyfield.bin $SIGKEY_OFFSET)
echo "signatureKey_hex: $sigkey_hex"
sigkey_ascii=$(echo "$sigkey_hex" | xxd -r -p 2>/dev/null | sed 's/[^[:print:]]/./g')
echo "signatureKey: $sigkey_ascii"
# signature ([string][string])
read sigfield_hex OFFSET LEN < <(read_ssh_string "$CERTBIN" $OFFSET)
echo $sigfield_hex | xxd -r -p > sigfield.bin
SIG_OFFSET=0
read sigtype_hex SIG_OFFSET LEN < <(read_ssh_string sigfield.bin $SIG_OFFSET)
read sig_hex SIG_OFFSET LEN < <(read_ssh_string sigfield.bin $SIG_OFFSET)
echo "signature_hex: $sig_hex"

# Cleanup
test -f $PUBKEYFIELD_BIN && rm $PUBKEYFIELD_BIN
test -f sigkeyfield.bin && rm sigkeyfield.bin
test -f sigfield.bin && rm sigfield.bin
