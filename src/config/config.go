package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Provider is an exported interface representing a single OIDC provider configuration.
// Concrete provider implementations are unexported inside this package.
type Provider interface {
	GetID() string
	GetName() string
	SetName(string)
	GetClientID() string
	SetClientID(string)
	GetClientSecret() string
	SetClientSecret(string)
	GetIssuer() string
	SetIssuer(string)
}

// Store is an exported interface for persisting and loading provider lists.
type Store interface {
	Load() ([]Provider, error)
	Save([]Provider) error
	Path() string
}

// provider is the package-private concrete representation used for JSON marshaling.
type provider struct {
	ID           string `json:"id"`
	Provider     string `json:"provider"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Issuer       string `json:"issuer"`
}

// fileStore implements Store and persists configuration to a JSON file.
type fileStore struct {
	path string
}

func defaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".openpubkey-agent.json"), nil
}

// NewProviderID returns a timestamp-based provider id.
func NewProviderID() string {
	return time.Now().UTC().Format("20060102T150405.000000000")
}

// NewProvider creates a Provider with an auto-generated id.
func NewProvider(name, clientID, clientSecret, issuer string) Provider {
	return &provider{ID: NewProviderID(), Provider: name, ClientID: clientID, ClientSecret: clientSecret, Issuer: issuer}
}

// NewProviderWithID creates a Provider with the supplied id.
func NewProviderWithID(id, name, clientID, clientSecret, issuer string) Provider {
	return &provider{ID: id, Provider: name, ClientID: clientID, ClientSecret: clientSecret, Issuer: issuer}
}

// NewFileStore returns a Store writing to the given path. If path is empty the default path is used.
func NewFileStore(path string) (Store, error) {
	if path == "" {
		p, err := defaultPath()
		if err != nil {
			return nil, err
		}
		path = p
	}
	return &fileStore{path: path}, nil
}

// NewDefaultFileStore returns a Store for the default config path and the path used.
func NewDefaultFileStore() (Store, string, error) {
	p, err := defaultPath()
	if err != nil {
		return nil, "", err
	}
	return &fileStore{path: p}, p, nil
}

// Load reads configuration from the store's path. If the file does not exist,
// an empty slice is returned without error.
func (fs *fileStore) Load() ([]Provider, error) {
	b, err := os.ReadFile(fs.path)
	if err != nil {
		if os.IsNotExist(err) {
			return []Provider{}, nil
		}
		return nil, err
	}
	var cfg struct {
		Providers []provider `json:"providers"`
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	res := make([]Provider, 0, len(cfg.Providers))
	for i := range cfg.Providers {
		// take address of slice element
		res = append(res, &cfg.Providers[i])
	}
	return res, nil
}

// Save writes the providers slice to the store's path.
func (fs *fileStore) Save(providers []Provider) error {
	cp := make([]provider, 0, len(providers))
	for _, pr := range providers {
		if p, ok := pr.(*provider); ok {
			cp = append(cp, *p)
			continue
		}
		cp = append(cp, provider{
			ID:           pr.GetID(),
			Provider:     pr.GetName(),
			ClientID:     pr.GetClientID(),
			ClientSecret: pr.GetClientSecret(),
			Issuer:       pr.GetIssuer(),
		})
	}
	out := struct {
		Providers []provider `json:"providers"`
	}{Providers: cp}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(fs.path, b, 0600)
}

func (fs *fileStore) Path() string { return fs.path }

// Provider interface methods on provider struct
func (p *provider) GetID() string            { return p.ID }
func (p *provider) GetName() string          { return p.Provider }
func (p *provider) SetName(v string)         { p.Provider = v }
func (p *provider) GetClientID() string      { return p.ClientID }
func (p *provider) SetClientID(v string)     { p.ClientID = v }
func (p *provider) GetClientSecret() string  { return p.ClientSecret }
func (p *provider) SetClientSecret(v string) { p.ClientSecret = v }
func (p *provider) GetIssuer() string        { return p.Issuer }
func (p *provider) SetIssuer(v string)       { p.Issuer = v }
