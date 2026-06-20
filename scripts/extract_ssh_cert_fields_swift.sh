#!/bin/bash
# extract_ssh_cert_fields_swift.sh
# Extract and display fields from an OpenSSH Ed25519 certificate (binary format)
# Usage: ./scripts/extract_ssh_cert_fields_swift.sh cert_swift.bin

set -euo pipefail

CERT_FILE="$1"

# Helper: read SSH string (4 bytes len + data)
read_ssh_string() {
  local offset="$1"
  local file="$2"
  local len_hex=$(dd if="$file" bs=1 skip=$offset count=4 2>/dev/null | xxd -p)
  local len=$((0x$len_hex))
  local str=$(dd if="$file" bs=1 skip=$(($offset+4)) count=$len 2>/dev/null | xxd -p)
  echo "$len $str"
}

# Helper: read uint64 (8 bytes, big endian)
read_uint64() {
  local offset="$1"
  local file="$2"
  dd if="$file" bs=1 skip=$offset count=8 2>/dev/null | xxd -p
}

# Helper: read uint32 (4 bytes, big endian)
read_uint32() {
  local offset="$1"
  local file="$2"
  dd if="$file" bs=1 skip=$offset count=4 2>/dev/null | xxd -p
}

# Helper: read uint8 (1 byte)
read_uint8() {
  local offset="$1"
  local file="$2"
  dd if="$file" bs=1 skip=$offset count=1 2>/dev/null | xxd -p
}

# Extraction
OFFSET=0

# 1. key type (SSH string)
read keytype_len keytype_hex < <(read_ssh_string $OFFSET "$CERT_FILE")
keytype=$(echo "$keytype_hex" | xxd -r -p)
echo "keytype: $keytype"
OFFSET=$((OFFSET+4+keytype_len))

# 2. nonce (SSH string)
read nonce_len nonce_hex < <(read_ssh_string $OFFSET "$CERT_FILE")
echo "nonce: $nonce_hex"
OFFSET=$((OFFSET+4+nonce_len))

# 3. public key (32 bytes)
pubkey_hex=$(dd if="$CERT_FILE" bs=1 skip=$OFFSET count=32 2>/dev/null | xxd -p)
echo "publicKey: $pubkey_hex"
OFFSET=$((OFFSET+32))

# 4. serial (uint64)
serial_hex=$(read_uint64 $OFFSET "$CERT_FILE")
echo "serial: $serial_hex"
OFFSET=$((OFFSET+8))

# 5. type (uint32)
type_hex=$(read_uint32 $OFFSET "$CERT_FILE")
echo "type: $type_hex"
OFFSET=$((OFFSET+4))

# 6. key id (SSH string)
read keyid_len keyid_hex < <(read_ssh_string $OFFSET "$CERT_FILE")
keyid=$(echo "$keyid_hex" | xxd -r -p)
echo "keyId: $keyid"
OFFSET=$((OFFSET+4+keyid_len))

# 7. valid principals (SSH string)
read principals_len principals_hex < <(read_ssh_string $OFFSET "$CERT_FILE")
principals=$(echo "$principals_hex" | xxd -r -p)
echo "validPrincipals: $principals"
OFFSET=$((OFFSET+4+principals_len))

# 8. valid after (uint64)
valid_after_hex=$(read_uint64 $OFFSET "$CERT_FILE")
echo "validAfter: $valid_after_hex"
OFFSET=$((OFFSET+8))

# 9. valid before (uint64)
valid_before_hex=$(read_uint64 $OFFSET "$CERT_FILE")
echo "validBefore: $valid_before_hex"
OFFSET=$((OFFSET+8))

# 10. critical options (SSH string)
read critopt_len critopt_hex < <(read_ssh_string $OFFSET "$CERT_FILE")
critopt=$(echo "$critopt_hex" | xxd -r -p)
echo "criticalOptions: $critopt"
OFFSET=$((OFFSET+4+critopt_len))

# 11. extensions (SSH string)
read ext_len ext_hex < <(read_ssh_string $OFFSET "$CERT_FILE")
ext=$(echo "$ext_hex" | xxd -r -p)
echo "extensions: $ext"
OFFSET=$((OFFSET+4+ext_len))

# 12. reserved (SSH string)
read reserved_len reserved_hex < <(read_ssh_string $OFFSET "$CERT_FILE")
reserved=$(echo "$reserved_hex" | xxd -r -p)
echo "reserved: $reserved"
OFFSET=$((OFFSET+4+reserved_len))

# 13. signature key (SSH string)
read sigkey_len sigkey_hex < <(read_ssh_string $OFFSET "$CERT_FILE")
sigkey=$(echo "$sigkey_hex" | xxd -r -p)
echo "signatureKey: $sigkey"
OFFSET=$((OFFSET+4+sigkey_len))

# 14. signature (SSH string)
read sig_len sig_hex < <(read_ssh_string $OFFSET "$CERT_FILE")
sig=$(echo "$sig_hex" | xxd -r -p)
echo "signature: $sig"
OFFSET=$((OFFSET+4+sig_len))

# 15. comment (SSH string, if present)
if [ $(stat -f%z "$CERT_FILE") -gt $OFFSET ]; then
  read comment_len comment_hex < <(read_ssh_string $OFFSET "$CERT_FILE")
  comment=$(echo "$comment_hex" | xxd -r -p)
  echo "comment: $comment"
fi
