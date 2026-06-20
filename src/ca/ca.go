package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
)

// CA defines the public interface for a certificate authority used in the project.
type CA interface {
	Sign([]byte) []byte
	Public() ed25519.PublicKey
	PublicHex() string
}

type caImpl struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

func caKeyPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".openpubkey-ca.key")
}

// LoadOrCreate returns a CA implementation (interface). The underlying struct is unexported.
func LoadOrCreate() (CA, error) {
	p := caKeyPath()
	if data, err := os.ReadFile(p); err == nil && len(data) == ed25519.PrivateKeySize {
		priv := ed25519.PrivateKey(data)
		pub := priv.Public().(ed25519.PublicKey)
		return &caImpl{private: priv, public: pub}, nil
	}
	// create
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	// write private raw (64 bytes)
	_ = os.MkdirAll(filepath.Dir(p), 0700)
	_ = os.WriteFile(p, priv, 0600)
	return &caImpl{private: priv, public: pub}, nil
}

func (c *caImpl) Sign(b []byte) []byte {
	return ed25519.Sign(c.private, b)
}

func (c *caImpl) Public() ed25519.PublicKey {
	return c.public
}

func (c *caImpl) PublicHex() string {
	return hex.EncodeToString(c.public)
}
