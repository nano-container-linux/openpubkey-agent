package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"
)

// AuthWithBrowser performs an OIDC/OAuth2 Authorization Code flow with PKCE using the provided
// client id/secret and an authorization URL (authorize endpoint or issuer URL). It opens the
// system browser, starts a local HTTP server, receives the code and exchanges it for a token.
func AuthWithBrowser(clientID, clientSecret, authURL string) (string, error) {
	// discovery: try to find token endpoint
	tokenEndpoint, err := discoverTokenEndpoint(authURL)
	if err != nil {
		// fallbacks for common providers
		if strings.Contains(authURL, "github.com") {
			tokenEndpoint = "https://github.com/login/oauth/access_token"
		} else if strings.Contains(authURL, "google") {
			tokenEndpoint = "https://oauth2.googleapis.com/token"
		} else {
			return "", fmt.Errorf("could not discover token endpoint: %v", err)
		}
	}

	// generate PKCE code verifier and challenge
	codeVerifier, codeChallenge, err := generatePKCE()
	if err != nil {
		return "", err
	}

	// start local server on loopback
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	state := randomStringURL(12)

	// build authorize URL
	v := url.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", clientID)
	v.Set("redirect_uri", redirectURI)
	v.Set("scope", "openid profile email")
	v.Set("state", state)
	v.Set("code_challenge", codeChallenge)
	v.Set("code_challenge_method", "S256")
	authFull := authURL
	if strings.Contains(authURL, "?") {
		authFull = authURL + "&" + v.Encode()
	} else {
		authFull = authURL + "?" + v.Encode()
	}

	// start HTTP server to receive callback
	ch := make(chan string)
	srv := &http.Server{}
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("state") != state {
			w.WriteHeader(400)
			io.WriteString(w, "invalid state")
			return
		}
		code := q.Get("code")
		if code == "" {
			w.WriteHeader(400)
			io.WriteString(w, "missing code")
			return
		}
		io.WriteString(w, "You may close this window and return to the app.")
		ch <- code
	})

	// serve in background
	go func() {
		_ = srv.Serve(ln)
	}()
	defer srv.Close()

	// open browser
	_ = exec.Command("open", authFull).Start()

	// wait for code or timeout
	select {
	case code := <-ch:
		// exchange code for token
		tok, err := exchangeCodeForToken(tokenEndpoint, clientID, clientSecret, code, redirectURI, codeVerifier)
		if err != nil {
			return "", err
		}
		return tok, nil
	case <-time.After(120 * time.Second):
		return "", errors.New("timeout waiting for authorization response")
	}
}

func discoverTokenEndpoint(authURL string) (string, error) {
	u, err := url.Parse(authURL)
	if err != nil {
		return "", err
	}
	// try issuer discovery at origin/.well-known/openid-configuration
	issuer := u.Scheme + "://" + u.Host
	discURL := issuer + "./.well-known/openid-configuration"
	// the above is wrong in many cases: try path '/.well-known/openid-configuration'
	discURL = issuer + "/.well-known/openid-configuration"
	resp, err := http.Get(discURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("discovery returned %d", resp.StatusCode)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	if te, ok := body["token_endpoint"].(string); ok {
		return te, nil
	}
	return "", errors.New("token_endpoint not found in discovery")
}

func generatePKCE() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	ver := base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(ver))
	chal := base64.RawURLEncoding.EncodeToString(h[:])
	return ver, chal, nil
}

func randomStringURL(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)[:n]
}

func exchangeCodeForToken(tokenEndpoint, clientID, clientSecret, code, redirectURI, verifier string) (string, error) {
	v := url.Values{}
	v.Set("grant_type", "authorization_code")
	v.Set("code", code)
	v.Set("redirect_uri", redirectURI)
	v.Set("client_id", clientID)
	if clientSecret != "" {
		v.Set("client_secret", clientSecret)
	}
	v.Set("code_verifier", verifier)

	req, err := http.NewRequest("POST", tokenEndpoint, strings.NewReader(v.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	cli := &http.Client{Timeout: 15 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		// attempt to read body for error message
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(b))
	}
	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		// some endpoints (like GitHub) may return form-encoded responses
		b, _ := io.ReadAll(resp.Body)
		vals, _ := url.ParseQuery(string(b))
		if at := vals.Get("access_token"); at != "" {
			return at, nil
		}
		return "", err
	}
	if at, ok := out["access_token"].(string); ok && at != "" {
		return at, nil
	}
	if idt, ok := out["id_token"].(string); ok && idt != "" {
		return idt, nil
	}
	return "", errors.New("no token in response")
}
