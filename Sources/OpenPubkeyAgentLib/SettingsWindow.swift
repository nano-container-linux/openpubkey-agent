import Cocoa

public class SettingsWindow: NSWindow, NSWindowDelegate, NSComboBoxDelegate {
    private let providerCombo = NSComboBox(frame: NSRect(x: 20, y: 180, width: 240, height: 26))
    private let urlField = NSTextField(frame: NSRect(x: 20, y: 140, width: 240, height: 24))
    private let clientIdField = NSTextField(frame: NSRect(x: 20, y: 100, width: 240, height: 24))
    private let clientSecretField = NSSecureTextField(frame: NSRect(x: 20, y: 60, width: 240, height: 24))
    private let saveButton = NSButton(frame: NSRect(x: 40, y: 20, width: 80, height: 30))
    private let cancelButton = NSButton(frame: NSRect(x: 160, y: 20, width: 80, height: 30))
    private var onSave: ((String, String, String, String) -> Void)?

    public init(currentProvider: String?, currentClientId: String?, currentClientSecret: String?, currentUrl: String?, onSave: @escaping (String, String, String, String) -> Void) {
        let rect = NSRect(x: 0, y: 0, width: 280, height: 220)
        super.init(contentRect: rect, styleMask: [.titled, .closable], backing: .buffered, defer: false)
        self.title = "Settings"
        self.delegate = self
        self.onSave = onSave
        setupUI(currentProvider: currentProvider, currentClientId: currentClientId, currentClientSecret: currentClientSecret, currentUrl: currentUrl)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    private func setupUI(currentProvider: String?, currentClientId: String?, currentClientSecret: String?, currentUrl: String?) {
        providerCombo.addItems(withObjectValues: ["GitHub", "Google", "Microsoft", "Apple", "Generic"])
        providerCombo.completes = false
        providerCombo.selectItem(withObjectValue: currentProvider ?? "GitHub")
        providerCombo.toolTip = "OIDC Provider"
        providerCombo.delegate = self
        self.contentView?.addSubview(providerCombo)

        urlField.placeholderString = "OIDC Auth URL"
        urlField.isEditable = false
        urlField.stringValue = currentUrl ?? ""
        self.contentView?.addSubview(urlField)

        clientIdField.placeholderString = "Client ID"
        clientIdField.stringValue = currentClientId ?? ""
        self.contentView?.addSubview(clientIdField)

        clientSecretField.placeholderString = "Client Secret (optional)"
        clientSecretField.stringValue = currentClientSecret ?? ""
        self.contentView?.addSubview(clientSecretField)

        saveButton.title = "Save"
        saveButton.bezelStyle = .rounded
        saveButton.target = self
        saveButton.action = #selector(saveClicked)
        self.contentView?.addSubview(saveButton)

        cancelButton.title = "Cancel"
        cancelButton.bezelStyle = .rounded
        cancelButton.target = self
        cancelButton.action = #selector(cancelClicked)
        self.contentView?.addSubview(cancelButton)

        updateUrlField()
    }

    public func comboBoxSelectionDidChange(_ notification: Notification) {
        updateUrlField()
    }

    private func updateUrlField() {
        let provider = providerCombo.stringValue
        if provider == "GitHub" {
            urlField.stringValue = "https://github.com/login/oauth/authorize"
            urlField.isEditable = false
        } else if provider == "Google" {
            urlField.stringValue = "https://accounts.google.com/o/oauth2/v2/auth"
            urlField.isEditable = false
        } else if provider == "Microsoft" {
            urlField.stringValue = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
            urlField.isEditable = false
        } else if provider == "Apple" {
            urlField.stringValue = "https://appleid.apple.com/auth/authorize"
            urlField.isEditable = false
        } else {
            urlField.stringValue = ""
            urlField.isEditable = true
        }
    }

    public func runModal() {
        let app = NSApplication.shared
        app.activate(ignoringOtherApps: true)
        app.runModal(for: self)
    }

    @objc private func saveClicked() {
        let provider = providerCombo.stringValue
        let clientId = clientIdField.stringValue
        let clientSecret = clientSecretField.stringValue
        let url = urlField.stringValue
        onSave?(provider, clientId, clientSecret, url)
        self.orderOut(nil)
        NSApp.stopModal()
    }

    @objc private func cancelClicked() {
        self.orderOut(nil)
        NSApp.stopModal()
    }

    public func windowWillClose(_ notification: Notification) {
        NSApp.stopModal()
    }
}
