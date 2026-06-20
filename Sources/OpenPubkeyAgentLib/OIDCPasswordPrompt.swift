// OIDCPasswordPrompt.swift
// OIDC password entry window (macOS)

import Cocoa

public class OIDCPasswordPrompt: NSWindow, NSWindowDelegate {
    private let passwordField = NSSecureTextField(frame: NSRect(x: 20, y: 60, width: 240, height: 24))
    private let okButton = NSButton(frame: NSRect(x: 100, y: 20, width: 80, height: 30))
    private var completion: ((String?) -> Void)?

    public init() {
        let rect = NSRect(x: 0, y: 0, width: 280, height: 110)
        super.init(contentRect: rect, styleMask: [.titled, .closable], backing: .buffered, defer: false)
        self.title = "OIDC Password"
        self.delegate = self
        setupUI()
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    private func setupUI() {
        passwordField.placeholderString = "OIDC Password"
        passwordField.target = self
        passwordField.action = #selector(okClicked)
        self.contentView?.addSubview(passwordField)

        okButton.title = "OK"
        okButton.bezelStyle = .rounded
        okButton.target = self
        okButton.action = #selector(okClicked)
        self.contentView?.addSubview(okButton)
    }

    public func runModal(completion: @escaping (String?) -> Void) {
        self.completion = completion
        let app = NSApplication.shared
        app.activate(ignoringOtherApps: true)
        app.runModal(for: self)
    }

    @objc private func okClicked() {
        completion?(passwordField.stringValue.isEmpty ? nil : passwordField.stringValue)
        self.orderOut(nil)
        NSApp.stopModal()
    }

    public func windowWillClose(_ notification: Notification) {
        completion?(nil)
        NSApp.stopModal()
    }
}
