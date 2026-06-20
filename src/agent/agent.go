package agent

import (
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"crypto/ed25519"
	"crypto/rand"

	"github.com/nano-container-linux/openpubkey-agent/cert"
)

const (
	msgRequestIdentities = 11
	msgIdentitiesAnswer  = 12
	msgSignRequest       = 13
	msgSignResponse      = 14
	msgAddIdentity       = 17
	msgFailure           = 5
)

const msgSuccess = 6

// Agent defines the public interface for the SSH agent.
type Agent interface {
	Start() error
	SetKeyAndCert(privateKey []byte, certificate []byte) error
}

type agent struct {
	socketPath string
	listener   net.Listener

	mu          sync.RWMutex
	privateKey  ed25519.PrivateKey
	publicKey   ed25519.PublicKey
	certificate []byte
}

func NewAgent(socketPath string) Agent {
	return &agent{socketPath: socketPath}
}

func GenerateEd25519KeyPair() (pub []byte, priv []byte, err error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return public, private, nil
}

func (a *agent) Start() error {
	// ensure old socket removed
	_ = os.Remove(a.socketPath)
	ln, err := net.Listen("unix", a.socketPath)
	if err != nil {
		return err
	}
	a.listener = ln
	// export SSH_AUTH_SOCK
	_ = os.Setenv("SSH_AUTH_SOCK", a.socketPath)
	go a.acceptLoop()
	return nil
}

func (a *agent) acceptLoop() {
	for {
		conn, err := a.listener.Accept()
		if err != nil {
			log.Printf("agent accept error: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go a.handleConn(conn)
	}
}

func (a *agent) handleConn(c net.Conn) {
	defer c.Close()
	for {
		var lenBuf [4]byte
		if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
			if err != io.EOF {
				// log.Printf("read length err: %v", err)
			}
			return
		}
		msgLen := binary.BigEndian.Uint32(lenBuf[:])
		msg := make([]byte, msgLen)
		if _, err := io.ReadFull(c, msg); err != nil {
			log.Printf("read msg err: %v", err)
			return
		}
		if len(msg) == 0 {
			continue
		}
		switch msg[0] {
		case msgRequestIdentities:
			a.handleRequestIdentities(c)
		case msgSignRequest:
			a.handleSignRequest(c, msg)
		case msgAddIdentity:
			a.handleAddIdentity(c, msg)
		default:
			// respond failure
			out := []byte{msgFailure}
			writePacket(c, out)
		}
	}
}

func (a *agent) handleAddIdentity(c net.Conn, msg []byte) {
	// parse: byte type; string key_type; string pub; string priv; string comment OR certificate variant
	idx := 1
	keyType, n, err := readString(msg, idx)
	if err != nil {
		writePacket(c, []byte{msgFailure})
		return
	}
	idx = n
	kt := string(keyType)
	switch kt {
	case "ssh-ed25519":
		pub, n2, err := readString(msg, idx)
		if err != nil {
			writePacket(c, []byte{msgFailure})
			return
		}
		idx = n2
		priv, n3, err := readString(msg, idx)
		if err != nil {
			writePacket(c, []byte{msgFailure})
			return
		}
		idx = n3
		_, n4, err := readString(msg, idx) // comment
		if err != nil {
			writePacket(c, []byte{msgFailure})
			return
		}
		_ = n4
		a.mu.Lock()
		if len(pub) == ed25519.PublicKeySize {
			a.publicKey = ed25519.PublicKey(pub)
		}
		if len(priv) == ed25519.PrivateKeySize {
			a.privateKey = ed25519.PrivateKey(priv)
			// ensure public matches private if not set
			if len(a.publicKey) != ed25519.PublicKeySize {
				a.publicKey = a.privateKey.Public().(ed25519.PublicKey)
			}
		} else {
			// If priv not raw, still store raw bytes in privateKey variable
			a.privateKey = ed25519.PrivateKey(priv)
		}
		a.certificate = nil
		a.mu.Unlock()
		writePacket(c, []byte{msgSuccess})
		return
	case cert.SSH_CERT_TYPE_ED25519:
		pub, n2, err := readString(msg, idx)
		if err != nil {
			writePacket(c, []byte{msgFailure})
			return
		}
		idx = n2
		priv, n3, err := readString(msg, idx)
		if err != nil {
			writePacket(c, []byte{msgFailure})
			return
		}
		idx = n3
		_, n4, err := readString(msg, idx) // comment
		if err != nil {
			writePacket(c, []byte{msgFailure})
			return
		}
		_ = n4
		a.mu.Lock()
		a.certificate = pub
		if inner := extractEd25519PubFromCert(pub); len(inner) == ed25519.PublicKeySize {
			a.publicKey = ed25519.PublicKey(inner)
		}
		if len(priv) == ed25519.PrivateKeySize {
			a.privateKey = ed25519.PrivateKey(priv)
		}
		a.mu.Unlock()
		writePacket(c, []byte{msgSuccess})
		return
	default:
		writePacket(c, []byte{msgFailure})
		return
	}
}

// extractEd25519PubFromCert attempts to parse a certificate blob and return the inner ed25519 public key
func extractEd25519PubFromCert(blob []byte) []byte {
	// blob is ssh-string(type) + content
	i := 0
	if i+4 > len(blob) {
		return nil
	}
	topLen := int(binary.BigEndian.Uint32(blob[i : i+4]))
	i += 4
	if i+topLen > len(blob) {
		return nil
	}
	typeData := blob[i : i+topLen]
	i += topLen
	if string(typeData) != cert.SSH_CERT_TYPE_ED25519 {
		// may still be top-level content (no type prefix)
		i = 0
	}
	// read public key field: skip a string then read pubField
	// read a string (public key field or something)
	if i+4 > len(blob) {
		return nil
	}
	if idxPubLen := int(binary.BigEndian.Uint32(blob[i : i+4])); idxPubLen > 0 {
		// attempt to skip that
		// but to mimic Swift, readString twice
	}
	// Use a simple scanner: find first occurrence of inner ssh-ed25519 type and then read next string
	// naive parse: scan for the bytes of "ssh-ed25519" and then read the following ssh-string
	needle := []byte("ssh-ed25519")
	for j := 0; j+len(needle) <= len(blob); j++ {
		if string(blob[j:j+len(needle)]) == string(needle) {
			// found inner type; the next field should be a ssh-string containing pubkey
			// find next 4-byte length just after j+len(needle)
			// but actual encoding is ssh-string(type) + ssh-string(pubField)
			// backtrack to find length prefix for this inner type
			// find k such that blob[k:k+4] equals length of inner type and k+4+len(needle)==j
			for k := j - 8; k >= 0 && k+4 < len(blob); k-- {
				l := int(binary.BigEndian.Uint32(blob[k : k+4]))
				if k+4+l == j {
					// next after inner type is at j+len(needle); then there is a 4-byte length and pub bytes
					pubLenIdx := j + len(needle)
					if pubLenIdx+4 > len(blob) {
						return nil
					}
					pubLen := int(binary.BigEndian.Uint32(blob[pubLenIdx : pubLenIdx+4]))
					pubStart := pubLenIdx + 4
					if pubStart+pubLen > len(blob) {
						return nil
					}
					return blob[pubStart : pubStart+pubLen]
				}
			}
		}
	}
	return nil
}

func writePacket(w io.Writer, payload []byte) error {
	var head [4]byte
	binary.BigEndian.PutUint32(head[:], uint32(len(payload)))
	if _, err := w.Write(head[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func (a *agent) handleRequestIdentities(c net.Conn) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	idents := make([][]byte, 0)
	comments := make([]string, 0)
	if a.publicKey != nil {
		// construct ssh-ed25519 key blob: string("ssh-ed25519") + string(pub)
		var b []byte
		b = append(b, sshString([]byte("ssh-ed25519"))...)
		b = append(b, sshString(a.publicKey)...)
		idents = append(idents, b)
		comments = append(comments, "openpubkey-key")
	}
	if a.certificate != nil {
		idents = append(idents, a.certificate)
		comments = append(comments, "openpubkey-agent")
	}
	// build response
	var payload []byte
	payload = append(payload, byte(msgIdentitiesAnswer))
	var cnt [4]byte
	binary.BigEndian.PutUint32(cnt[:], uint32(len(idents)))
	payload = append(payload, cnt[:]...)
	for i, id := range idents {
		payload = append(payload, sshString(id)...)
		payload = append(payload, sshString([]byte(comments[i]))...)
	}
	_ = writePacket(c, payload)
}

func (a *agent) handleSignRequest(c net.Conn, msg []byte) {
	// parse: byte type; string key_blob; string data; uint32 flags
	idx := 1
	keyBlob, n1, err := readString(msg, idx)
	if err != nil {
		writePacket(c, []byte{msgFailure})
		return
	}
	idx = n1
	dataToSign, n2, err := readString(msg, idx)
	if err != nil {
		writePacket(c, []byte{msgFailure})
		return
	}
	idx = n2
	// skip flags
	// (ensure enough bytes)
	if idx+4 > len(msg) {
		writePacket(c, []byte{msgFailure})
		return
	}
	// flags := binary.BigEndian.Uint32(msg[idx:idx+4])
	// idx += 4

	// decide whether keyBlob corresponds to our key or cert
	a.mu.RLock()
	pub := a.publicKey
	cert := a.certificate
	priv := a.privateKey
	a.mu.RUnlock()

	if pub == nil || priv == nil {
		writePacket(c, []byte{msgFailure})
		return
	}

	// quick check: does keyBlob contain public key bytes?
	found := false
	if len(pub) > 0 && bytesContains(keyBlob, pub) {
		found = true
	}
	if !found && cert != nil && bytesContains(keyBlob, cert) {
		found = true
	}
	if !found {
		writePacket(c, []byte{msgFailure})
		return
	}

	sig := ed25519.Sign(priv, dataToSign)
	// signature blob: string("ssh-ed25519") + string(sig)
	var sigBlob []byte
	sigBlob = append(sigBlob, sshString([]byte("ssh-ed25519"))...)
	sigBlob = append(sigBlob, sshString(sig)...)
	var payload []byte
	payload = append(payload, byte(msgSignResponse))
	payload = append(payload, sshString(sigBlob)...)
	_ = writePacket(c, payload)
}

func (a *agent) SetKeyAndCert(privateKey []byte, certificate []byte) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return errors.New("invalid private key length")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.privateKey = ed25519.PrivateKey(privateKey)
	a.publicKey = a.privateKey.Public().(ed25519.PublicKey)
	a.certificate = certificate
	return nil
}

// helpers

func sshString(b []byte) []byte {
	var out = make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out[:4], uint32(len(b)))
	copy(out[4:], b)
	return out
}

func readString(msg []byte, idx int) ([]byte, int, error) {
	if idx+4 > len(msg) {
		return nil, 0, io.ErrUnexpectedEOF
	}
	l := int(binary.BigEndian.Uint32(msg[idx : idx+4]))
	idx += 4
	if idx+l > len(msg) {
		return nil, 0, io.ErrUnexpectedEOF
	}
	s := msg[idx : idx+l]
	idx += l
	return s, idx, nil
}

func bytesContains(hay []byte, needle []byte) bool {
	if len(needle) == 0 {
		return false
	}
	for i := 0; i+len(needle) <= len(hay); i++ {
		if string(hay[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}
