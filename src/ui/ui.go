package ui

import (
	"log"

	"github.com/progrium/darwinkit/helper/action"
	"github.com/progrium/darwinkit/helper/layout"
	"github.com/progrium/darwinkit/macos/appkit"
	"github.com/progrium/darwinkit/macos/foundation"
	"github.com/progrium/darwinkit/objc"

	"github.com/nano-container-linux/openpubkey-agent/config"
)

// ShowPasswordPrompt displays a small window with a secure text field and calls onSubmit(password)
// when the user clicks OK. This is non-blocking and safe to call from menu handlers.
func ShowPasswordPrompt(onSubmit func(string)) {
	w := appkit.NewWindowWithSize(360, 140)
	objc.Retain(&w)
	w.SetTitle("OIDC Password")
	// secure field
	sf := appkit.NewSecureTextField()
	sf.SetTranslatesAutoresizingMaskIntoConstraints(false)
	w.ContentView().AddSubview(sf)
	// buttons
	ok := appkit.NewButtonWithTitle("OK")
	ok.SetTranslatesAutoresizingMaskIntoConstraints(false)
	cancel := appkit.NewButtonWithTitle("Cancel")
	cancel.SetTranslatesAutoresizingMaskIntoConstraints(false)
	w.ContentView().AddSubview(ok)
	w.ContentView().AddSubview(cancel)

	// layout
	layout.PinAnchorTo(sf.TopAnchor(), w.ContentView().TopAnchor(), -20)
	layout.PinAnchorTo(sf.LeftAnchor(), w.ContentView().LeftAnchor(), 20)
	layout.PinAnchorTo(sf.RightAnchor(), w.ContentView().RightAnchor(), -20)
	layout.PinAnchorTo(ok.BottomAnchor(), w.ContentView().BottomAnchor(), -12)
	layout.PinAnchorTo(ok.RightAnchor(), w.ContentView().RightAnchor(), -20)
	layout.PinAnchorTo(cancel.BottomAnchor(), w.ContentView().BottomAnchor(), -12)
	layout.PinAnchorTo(cancel.RightAnchor(), ok.LeftAnchor(), -10)

	action.Set(ok, func(sender objc.Object) {
		val := sf.StringValue()
		w.Close()
		onSubmit(val)
	})
	action.Set(cancel, func(sender objc.Object) {
		w.Close()
	})

	w.MakeKeyAndOrderFront(nil)
	w.Center()
}

// OpenSettingsWindow opens a simple settings window (placeholder)
func OpenSettingsWindow() {
	store, _, err := config.NewDefaultFileStore()
	if err != nil {
		log.Printf("failed to create config store: %v", err)
	}
	var providers []config.Provider
	if store != nil {
		providers, err = store.Load()
		if err != nil {
			log.Printf("failed to load config: %v", err)
			providers = []config.Provider{}
		}
	} else {
		providers = []config.Provider{}
	}

	w := appkit.NewWindowWithSize(720, 380)
	objc.Retain(&w)
	w.SetTitle("OIDC Providers & Keys")

	// Build split view
	frame := foundation.Rect{Size: foundation.Size{Width: 720, Height: 380}}
	split := appkit.NewSplitViewWithFrame(frame)
	split.SetVertical(true)
	split.SetTranslatesAutoresizingMaskIntoConstraints(false)
	w.ContentView().AddSubview(split)

	// Left pane: scroll + stack of provider buttons
	left := appkit.NewViewWithFrame(foundation.Rect{Size: foundation.Size{Width: 260, Height: 360}})
	left.SetTranslatesAutoresizingMaskIntoConstraints(false)
	scroll := appkit.NewScrollViewWithFrame(foundation.Rect{Size: foundation.Size{Width: 260, Height: 300}})
	scroll.SetHasVerticalScroller(true)
	contentView := appkit.NewViewWithFrame(foundation.Rect{Size: foundation.Size{Width: 240, Height: 300}})
	scroll.SetDocumentView(contentView)
	left.AddSubview(scroll)

	addBtn := appkit.NewButtonWithTitle("+")
	removeBtn := appkit.NewButtonWithTitle("–")
	addBtn.SetTranslatesAutoresizingMaskIntoConstraints(false)
	removeBtn.SetTranslatesAutoresizingMaskIntoConstraints(false)
	left.AddSubview(addBtn)
	left.AddSubview(removeBtn)

	// Right pane: details
	right := appkit.NewViewWithFrame(foundation.Rect{Size: foundation.Size{Width: 440, Height: 360}})
	right.SetTranslatesAutoresizingMaskIntoConstraints(false)

	titleLbl := appkit.NewLabel("")
	titleLbl.SetTranslatesAutoresizingMaskIntoConstraints(false)
	providerField := appkit.NewTextField()
	clientIdField := appkit.NewTextField()
	clientSecretField := appkit.NewSecureTextField()
	issuerField := appkit.NewTextField()
	saveBtn := appkit.NewButtonWithTitle("Save")
	testBtn := appkit.NewButtonWithTitle("Test")

	titleLbl.SetTranslatesAutoresizingMaskIntoConstraints(false)
	right.AddSubview(titleLbl)
	providerField.SetTranslatesAutoresizingMaskIntoConstraints(false)
	right.AddSubview(providerField)
	clientIdField.SetTranslatesAutoresizingMaskIntoConstraints(false)
	right.AddSubview(clientIdField)
	clientSecretField.SetTranslatesAutoresizingMaskIntoConstraints(false)
	right.AddSubview(clientSecretField)
	issuerField.SetTranslatesAutoresizingMaskIntoConstraints(false)
	right.AddSubview(issuerField)
	saveBtn.SetTranslatesAutoresizingMaskIntoConstraints(false)
	right.AddSubview(saveBtn)
	testBtn.SetTranslatesAutoresizingMaskIntoConstraints(false)
	right.AddSubview(testBtn)

	split.AddArrangedSubview(left)
	split.AddArrangedSubview(right)
	split.SetPositionOfDividerAtIndex(300, 0)

	// Provider list stack inside contentView
	stack := appkit.NewStackView()
	stack.SetOrientation(appkit.UserInterfaceLayoutOrientationVertical)
	stack.SetSpacing(8)
	stack.SetTranslatesAutoresizingMaskIntoConstraints(false)
	contentView.AddSubview(stack)

	selected := -1

	refreshList := func() {
		// remove arranged subviews
		for _, v := range stack.ArrangedSubviews() {
			stack.RemoveArrangedSubview(v)
			v.RemoveFromSuperview()
		}
		for i, p := range providers {
			btn := appkit.NewButtonWithTitle(p.GetName())
			btn.SetTranslatesAutoresizingMaskIntoConstraints(false)
			idx := i
			pLocal := p
			action.Set(btn, func(sender objc.Object) {
				selected = idx
				// populate fields
				titleLbl.SetStringValue(pLocal.GetName())
				providerField.SetStringValue(pLocal.GetName())
				clientIdField.SetStringValue(pLocal.GetClientID())
				clientSecretField.SetStringValue(pLocal.GetClientSecret())
				issuerField.SetStringValue(pLocal.GetIssuer())
			})
			stack.AddArrangedSubview(btn)
		}
	}

	// Add provider
	action.Set(addBtn, func(sender objc.Object) {
		np := config.NewProvider("New Provider", "", "", "")
		providers = append(providers, np)
		if store != nil {
			if err := store.Save(providers); err != nil {
				log.Printf("save config: %v", err)
			}
		}
		refreshList()
	})

	// Remove provider
	action.Set(removeBtn, func(sender objc.Object) {
		if selected < 0 || selected >= len(providers) {
			return
		}
		// remove
		providers = append(providers[:selected], providers[selected+1:]...)
		if store != nil {
			if err := store.Save(providers); err != nil {
				log.Printf("save config: %v", err)
			}
		}
		selected = -1
		titleLbl.SetStringValue("")
		providerField.SetStringValue("")
		clientIdField.SetStringValue("")
		clientSecretField.SetStringValue("")
		issuerField.SetStringValue("")
		refreshList()
	})

	// Save details
	action.Set(saveBtn, func(sender objc.Object) {
		if selected < 0 || selected >= len(providers) {
			return
		}
		p := providers[selected]
		p.SetName(providerField.StringValue())
		p.SetClientID(clientIdField.StringValue())
		p.SetClientSecret(clientSecretField.StringValue())
		p.SetIssuer(issuerField.StringValue())
		if store != nil {
			if err := store.Save(providers); err != nil {
				log.Printf("save config: %v", err)
			}
		}
		refreshList()
	})

	// Test button placeholder
	action.Set(testBtn, func(sender objc.Object) {
		log.Printf("test provider (placeholder)")
	})

	// Layout using simple anchors
	layout.PinAnchorTo(split.TopAnchor(), w.ContentView().TopAnchor(), -8)
	layout.PinAnchorTo(split.LeftAnchor(), w.ContentView().LeftAnchor(), 8)
	layout.PinAnchorTo(split.RightAnchor(), w.ContentView().RightAnchor(), -8)
	layout.PinAnchorTo(split.BottomAnchor(), w.ContentView().BottomAnchor(), 8)

	// stack layout inside contentView
	layout.PinAnchorTo(stack.TopAnchor(), contentView.TopAnchor(), -8)
	layout.PinAnchorTo(stack.LeftAnchor(), contentView.LeftAnchor(), 8)
	layout.PinAnchorTo(stack.RightAnchor(), contentView.RightAnchor(), -8)

	// right pane simple layout
	layout.PinAnchorTo(titleLbl.TopAnchor(), right.TopAnchor(), -20)
	layout.PinAnchorTo(titleLbl.LeftAnchor(), right.LeftAnchor(), 20)
	layout.PinAnchorTo(providerField.TopAnchor(), titleLbl.BottomAnchor(), -12)
	layout.PinAnchorTo(providerField.LeftAnchor(), right.LeftAnchor(), 20)
	layout.PinAnchorTo(providerField.RightAnchor(), right.RightAnchor(), -20)
	layout.PinAnchorTo(clientIdField.TopAnchor(), providerField.BottomAnchor(), -12)
	layout.PinAnchorTo(clientIdField.LeftAnchor(), right.LeftAnchor(), 20)
	layout.PinAnchorTo(clientIdField.RightAnchor(), right.RightAnchor(), -20)
	layout.PinAnchorTo(clientSecretField.TopAnchor(), clientIdField.BottomAnchor(), -12)
	layout.PinAnchorTo(clientSecretField.LeftAnchor(), right.LeftAnchor(), 20)
	layout.PinAnchorTo(clientSecretField.RightAnchor(), right.RightAnchor(), -20)
	layout.PinAnchorTo(issuerField.TopAnchor(), clientSecretField.BottomAnchor(), -12)
	layout.PinAnchorTo(issuerField.LeftAnchor(), right.LeftAnchor(), 20)
	layout.PinAnchorTo(issuerField.RightAnchor(), right.RightAnchor(), -20)
	layout.PinAnchorTo(saveBtn.BottomAnchor(), right.BottomAnchor(), -12)
	layout.PinAnchorTo(saveBtn.RightAnchor(), right.RightAnchor(), -20)
	layout.PinAnchorTo(testBtn.BottomAnchor(), right.BottomAnchor(), -12)
	layout.PinAnchorTo(testBtn.RightAnchor(), saveBtn.LeftAnchor(), -8)

	refreshList()

	w.MakeKeyAndOrderFront(nil)
	w.Center()
}
