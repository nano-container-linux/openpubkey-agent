package main

import (
	"log"
	"os"

	"github.com/nano-container-linux/openpubkey-agent/agent"
	"github.com/nano-container-linux/openpubkey-agent/ca"
	"github.com/nano-container-linux/openpubkey-agent/cert"
	"github.com/nano-container-linux/openpubkey-agent/oidc"
	"github.com/nano-container-linux/openpubkey-agent/ui"

	"github.com/progrium/darwinkit/macos"
	"github.com/progrium/darwinkit/macos/appkit"
	"github.com/progrium/darwinkit/objc"
)

func main() {
	ag := agent.NewAgent("/tmp/openpubkey-agent.sock")
	if err := ag.Start(); err != nil {
		log.Fatalf("failed to start agent: %v", err)
	}
	log.Println("SSH agent started at /tmp/openpubkey-agent.sock")

	macos.RunApp(func(app appkit.Application, delegate *appkit.ApplicationDelegate) {
		item := appkit.StatusBar_SystemStatusBar().StatusItemWithLength(appkit.VariableStatusItemLength)
		objc.Retain(&item)
		img := appkit.Image_ImageWithSystemSymbolNameAccessibilityDescription("lock.fill", "OpenPubkeyAgent")
		item.Button().SetImage(img)

		menu := appkit.NewMenuWithTitle("openpubkey")
		menu.AddItem(appkit.NewMenuItemWithAction("Login & Load SSH Key", "l", func(sender objc.Object) {
			// Try OIDC flow if env vars are set, otherwise fallback to password prompt
			clientID := os.Getenv("OIDC_CLIENT_ID")
			authURL := os.Getenv("OIDC_AUTH_URL")
			clientSecret := os.Getenv("OIDC_CLIENT_SECRET")
			if clientID != "" && authURL != "" {
				go func() {
					token, err := oidc.AuthWithBrowser(clientID, clientSecret, authURL)
					if err != nil {
						log.Printf("OIDC auth failed: %v", err)
						return
					}
					pub, priv, err := agent.GenerateEd25519KeyPair()
					if err != nil {
						log.Printf("keygen failed: %v", err)
						return
					}
					caObj, err := ca.LoadOrCreate()
					if err != nil {
						log.Printf("load ca failed: %v", err)
						return
					}
					certBlob, err := cert.CreateSignedCert(pub, "go-identity", []string{os.Getenv("USER")}, 0, ^uint64(0), map[string]string{"openpubkey-pktoken": token}, caObj)
					if err != nil {
						log.Printf("create cert failed: %v", err)
						return
					}
					if err := ag.SetKeyAndCert(priv, certBlob); err != nil {
						log.Printf("set key failed: %v", err)
						return
					}
					log.Printf("Loaded key and certificate into agent (OIDC)")
				}()
			} else {
				// Show password prompt and perform keygen+cert on submit
				ui.ShowPasswordPrompt(func(token string) {
					pub, priv, err := agent.GenerateEd25519KeyPair()
					if err != nil {
						log.Printf("keygen failed: %v", err)
						return
					}
					caObj, err := ca.LoadOrCreate()
					if err != nil {
						log.Printf("load ca failed: %v", err)
						return
					}
					certBlob, err := cert.CreateSignedCert(pub, "go-identity", []string{os.Getenv("USER")}, 0, ^uint64(0), map[string]string{"openpubkey-pktoken": token}, caObj)
					if err != nil {
						log.Printf("create cert failed: %v", err)
						return
					}
					if err := ag.SetKeyAndCert(priv, certBlob); err != nil {
						log.Printf("set key failed: %v", err)
						return
					}
					log.Printf("Loaded key and certificate into agent")
				})
			}
		}))

		menu.AddItem(appkit.NewMenuItemWithAction("Manage Providers & Keys", ",", func(sender objc.Object) {
			ui.OpenSettingsWindow()
		}))
		menu.AddItem(appkit.NewMenuItemWithAction("Quit", "q", func(sender objc.Object) { app.Terminate(nil) }))
		item.SetMenu(menu)
		app.SetActivationPolicy(appkit.ApplicationActivationPolicyAccessory)
	})
}
