package config

import (
	"os"
	"testing"
)

func TestSaveLoadRoundtrip(t *testing.T) {
	tmp, err := os.CreateTemp("", "openpubkey-config-*.json")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	path := tmp.Name()
	tmp.Close()
	defer os.Remove(path)

	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	orig := []Provider{
		NewProviderWithID("1", "github", "cid", "sec", "https://auth"),
		NewProviderWithID("2", "google", "gid", "gsec", "https://g"),
	}
	if err := store.Save(orig); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(loaded) != len(orig) {
		t.Fatalf("unexpected providers count: got %d want %d", len(loaded), len(orig))
	}
	for i := range orig {
		a := orig[i]
		b := loaded[i]
		if a.GetID() != b.GetID() || a.GetName() != b.GetName() || a.GetClientID() != b.GetClientID() || a.GetClientSecret() != b.GetClientSecret() || a.GetIssuer() != b.GetIssuer() {
			t.Fatalf("mismatch at index %d: got %+v want %+v", i, b, a)
		}
	}
}

func TestLoadNonexistent(t *testing.T) {
	store, err := NewFileStore("/path/does/not/exist.json")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	providers, err := store.Load()
	if err != nil {
		t.Fatalf("expected no error for nonexistent path, got: %v", err)
	}
	if len(providers) != 0 {
		t.Fatalf("expected empty providers for nonexistent path, got: %d", len(providers))
	}
}
