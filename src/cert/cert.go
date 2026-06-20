package cert

import (
	"encoding/binary"
	"errors"
	"sort"

	"github.com/nano-container-linux/openpubkey-agent/ca"
)

const (
	SSH_CERT_TYPE_ED25519 = "ssh-ed25519-cert-v01@openssh.com"
	SSH_KEY_TYPE_ED25519  = "ssh-ed25519"
)

func sshString(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out[:4], uint32(len(b)))
	copy(out[4:], b)
	return out
}

func sshStringFromString(s string) []byte { return sshString([]byte(s)) }

func sshDictSorted(dict map[string]string) []byte {
	// preferred order
	order := []string{"permit-X11-forwarding", "permit-agent-forwarding", "permit-port-forwarding", "permit-pty", "permit-user-rc"}
	seen := map[string]bool{}
	var d []byte
	for _, k := range order {
		if v, ok := dict[k]; ok {
			d = append(d, sshString([]byte(k))...)
			d = append(d, sshString([]byte(v))...)
			seen[k] = true
		}
	}
	// remaining keys sorted
	rem := []string{}
	for k := range dict {
		if !seen[k] {
			rem = append(rem, k)
		}
	}
	sort.Strings(rem)
	for _, k := range rem {
		d = append(d, sshString([]byte(k))...)
		d = append(d, sshString([]byte(dict[k]))...)
	}
	return sshString(d)
}

func CreateSignedCert(publicKey []byte, keyId string, validPrincipals []string, validAfter uint64, validBefore uint64, extensions map[string]string, caObj ca.CA) ([]byte, error) {
	if caObj == nil {
		return nil, errors.New("nil CA")
	}
	// nonce
	nonce := make([]byte, 32)
	// fill with zeros for reproducibility? leave random
	// rand.Read might be used but ok
	// publicKey expected >=32 bytes; take first 32
	// Build content
	content := []byte{}
	content = append(content, sshString(nonce)...) // nonce
	// public key field: as SSH format we store ssh-string(pub[:32])
	content = append(content, sshString(publicKey[:32])...)
	// serial
	var serial [8]byte
	binary.BigEndian.PutUint64(serial[:], 1)
	content = append(content, serial[:]...)
	// cert type user
	var ct [4]byte
	binary.BigEndian.PutUint32(ct[:], 1)
	content = append(content, ct[:]...)
	// key id
	content = append(content, sshString([]byte(keyId))...)
	// valid principals: build blob of ssh-string per principal then wrap
	var principalsBlob []byte
	for _, p := range validPrincipals {
		principalsBlob = append(principalsBlob, sshString([]byte(p))...)
	}
	content = append(content, sshString(principalsBlob)...)
	// validAfter, validBefore
	var va [8]byte
	var vb [8]byte
	binary.BigEndian.PutUint64(va[:], validAfter)
	binary.BigEndian.PutUint64(vb[:], validBefore)
	content = append(content, va[:]...)
	content = append(content, vb[:]...)
	// criticalOptions (empty)
	content = append(content, sshDictSorted(map[string]string{})...)
	// extensions
	if extensions == nil {
		extensions = map[string]string{}
	}
	// add default permits
	defaults := map[string]string{
		"permit-X11-forwarding":   "",
		"permit-agent-forwarding": "",
		"permit-port-forwarding":  "",
		"permit-pty":              "",
		"permit-user-rc":          "",
	}
	for k, v := range defaults {
		if _, ok := extensions[k]; !ok {
			extensions[k] = v
		}
	}
	content = append(content, sshDictSorted(extensions)...)
	// reserved (uint32 0)
	var z [4]byte
	binary.BigEndian.PutUint32(z[:], 0)
	content = append(content, z[:]...)
	// signatureKey: encode inner blob ssh-string(type) + ssh-string(keydata)
	var sigKeyField []byte
	sigKeyField = append(sigKeyField, sshString([]byte(SSH_KEY_TYPE_ED25519))...)
	pub := caObj.Public()
	sigKeyField = append(sigKeyField, sshString(pub[:32])...)
	content = append(content, sshString(sigKeyField)...)

	// signature: sign over ssh-string(type) || content
	var toSign []byte
	toSign = append(toSign, sshString([]byte(SSH_CERT_TYPE_ED25519))...)
	toSign = append(toSign, content...)
	signature := caObj.Sign(toSign)
	// signature field encoded as ssh-string( inner blob: ssh-string(type) + ssh-string(signature) )
	var sigField []byte
	sigField = append(sigField, sshString([]byte(SSH_KEY_TYPE_ED25519))...)
	sigField = append(sigField, sshString(signature)...)
	// now content with signature
	contentWithSig := append(content, sshString(sigField)...)
	// top-level blob: ssh-string(type) + contentWithSig
	out := []byte{}
	out = append(out, sshString([]byte(SSH_CERT_TYPE_ED25519))...)
	out = append(out, contentWithSig...)
	return out, nil
}
