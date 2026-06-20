#!/usr/bin/env bash
set -euo pipefail
if [ $# -ne 1 ]; then
  echo "Usage: $0 <cert.bin>" >&2
  exit 1
fi
f="$1"
filesz=$(wc -c < "$f")
echo "File: $f size=$filesz"
off=0
read_uint32() {
  dd if="$f" bs=1 skip=$off count=4 2>/dev/null | xxd -p -c4 | tr -d '\n' | awk '{print strtonum("0x"$0)}'
}
read_bytes() {
  local count=$1
  dd if="$f" bs=1 skip=$off count=$count 2>/dev/null | xxd -p -c $count
}
read_ssh_string() {
  local len_hex
  len_hex=$(dd if="$f" bs=1 skip=$off count=4 2>/dev/null | xxd -p -c4)
  local len=$((16#$len_hex))
  local start=$((off+4))
  printf "ssh-string at %d len=%d\n" $off $len
  dd if="$f" bs=1 skip=$start count=$len 2>/dev/null | xxd -p -c 32
  off=$((start+len))
}

# Read top-level key type and set offset to start of content
echo "-- top-level key type --"
len_hex=$(xxd -p -s 0 -l 4 "$f")
type_len=$((16#$len_hex))
off=$((4+type_len))
xxd -p -s 4 -l $type_len "$f"

echo "-- content fields (sequence) --"
# Now parse sequentially: nonce (ssh-string), pubkeyfield (ssh-string), serial(8), certType(4), keyId(ssh-string), principals(ssh-string), validAfter(8), validBefore(8), critopts(ssh-string), exts(ssh-string), reserved(4), sigKey(ssh-string), sig(ssh-string)

# nonce
echo "nonce:"; read_ssh_string
# pubkeyfield
echo "pubkeyfield:"; read_ssh_string
# serial (8 bytes)
echo "serial at $off bytes:"; dd if="$f" bs=1 skip=$off count=8 2>/dev/null | xxd -p -c8; off=$((off+8))
# certType (4)
echo "certType at $off:"; dd if="$f" bs=1 skip=$off count=4 2>/dev/null | xxd -p -c4; off=$((off+4))
# keyId
echo "keyId:"; read_ssh_string
# principals
echo "principals:"; read_ssh_string
# validAfter
echo "validAfter at $off:"; dd if="$f" bs=1 skip=$off count=8 2>/dev/null | xxd -p -c8; off=$((off+8))
# validBefore
echo "validBefore at $off:"; dd if="$f" bs=1 skip=$off count=8 2>/dev/null | xxd -p -c8; off=$((off+8))
# critopts
echo "criticalOptions:"; read_ssh_string
# extensions
echo "extensions:"; read_ssh_string
# reserved (4)
echo "reserved at $off:"; dd if="$f" bs=1 skip=$off count=4 2>/dev/null | xxd -p -c4; off=$((off+4))
# sigKey
echo "signatureKey:"; read_ssh_string
# signature
echo "signature:"; if [ $off -lt $filesz ]; then read_ssh_string || true; else echo "no signature (EOF)"; fi

echo "final offset=$off file_size=$filesz"
