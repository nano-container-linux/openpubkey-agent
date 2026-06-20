#!/bin/bash
# debug_extract.sh — verbose extractor without set -e
export LC_ALL=C
if [ $# -ne 1 ]; then
  echo "Usage: $0 <cert.bin>" >&2
  exit 1
fi
CERTBIN="$1"
echo "Parsing $CERTBIN (size=$(wc -c < "$CERTBIN"))"
read_ssh_string() {
  local file=$1; local offset=$2
  printf 'READ_SSH_STRING at offset=%d
' "$offset" >&2
  local len_hex
  len_hex=$(dd if="$file" bs=1 skip=$offset count=4 2>/dev/null | xxd -p -c 1000)
  printf 'LEN_HEX=%s
' "$len_hex" >&2
  local len=$((16#$len_hex))
  local data_offset=$((offset+4))
  dd if="$file" bs=1 skip=$data_offset count=$len 2>/dev/null | xxd -p -c 1000
  printf '\n%d\n%d\n' $((data_offset+len)) "$len"
}
read_ssh_string "$CERTBIN" 0 > /dev/null

echo "-- Now running full parse --"
OFFSET=0
read -r keytype_hex
read -r OFFSET
read -r LEN
echo "keytype_hex len=$LEN offset_after=$OFFSET"
keytype_ascii=$(echo "$keytype_hex" | xxd -r -p 2>/dev/null | sed 's/[^[:print:]]/./g')
echo "keytype: $keytype_ascii"

read -r nonce_hex
read -r OFFSET
read -r LEN
echo "nonce len=$LEN offset_after=$OFFSET"
echo "nonce_hex: $nonce_hex"

read -r pubkeyfield_hex
read -r OFFSET
read -r LEN
echo "pubfield len=$LEN offset_after=$OFFSET"

echo done
