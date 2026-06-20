import Cocoa

public class SettingsManagerWindow: NSWindow, NSWindowDelegate, NSTableViewDelegate, NSTableViewDataSource {
    // Custom row view to draw a rounded blue selection like the WireGuard UI
    private class ProviderRowView: NSTableRowView {
        override func drawSelection(in dirtyRect: NSRect) {
            guard isSelected else { return }
            let insetBounds = self.bounds.insetBy(dx: 6, dy: 4)
            let path = NSBezierPath(roundedRect: insetBounds, xRadius: 8, yRadius: 8)
            NSColor.systemBlue.setFill()
            path.fill()
        }
    }
    private var configs: [ProviderConfig]
    private let tableView = NSTableView()
    private let scrollView = NSScrollView()
    private let addButton = NSButton(title: "Add", target: nil, action: nil)
    private let editButton = NSButton(title: "Edit", target: nil, action: nil)
    private let removeButton = NSButton(title: "Remove", target: nil, action: nil)
    private let splitView = NSSplitView()
    // Detail fields
    private let detailProviderField = NSTextField(string: "")
    private let detailClientIdField = NSTextField(string: "")
    private let detailClientSecretField = NSSecureTextField(string: "")
    private let detailUrlField = NSTextField(string: "")
    private let detailTitleLabel = NSTextField(labelWithString: "")
    private let detailIconView = NSImageView()
    private let saveButton = NSButton(title: "Save", target: nil, action: nil)
    private let testButton = NSButton(title: "Test", target: nil, action: nil)
    private let onSave: ([ProviderConfig]) -> Void

    public init(configs: [ProviderConfig], onSave: @escaping ([ProviderConfig]) -> Void) {
        self.configs = configs
        self.onSave = onSave
        let rect = NSRect(x: 0, y: 0, width: 500, height: 320)
        super.init(contentRect: rect, styleMask: [.titled, .closable], backing: .buffered, defer: false)
        self.title = "OIDC Providers & Keys"
        self.delegate = self
        setupUI()
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    private func setupUI() {
        // table columns (icon + status dot + provider)
        let iconCol = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("icon"))
        iconCol.title = ""
        iconCol.width = 36
        iconCol.minWidth = 36
        let statusCol = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("status"))
        statusCol.title = ""
        statusCol.width = 18
        statusCol.minWidth = 18
        let providerCol = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("provider"))
        providerCol.title = "Provider"
        providerCol.width = 140
        tableView.addTableColumn(iconCol)
        tableView.addTableColumn(statusCol)
        tableView.addTableColumn(providerCol)
        tableView.delegate = self
        tableView.dataSource = self
        tableView.rowHeight = 42
        tableView.intercellSpacing = NSSize(width: 6, height: 6)
        tableView.headerView = nil
        tableView.usesAlternatingRowBackgroundColors = false
        tableView.selectionHighlightStyle = .regular
        scrollView.documentView = tableView
        scrollView.hasVerticalScroller = true
        // Build split view: left = table, right = details
        guard let content = self.contentView else { return }
        splitView.frame = content.bounds
        splitView.dividerStyle = .thin
        splitView.isVertical = true
        splitView.autoresizingMask = [.width, .height]

        // left pane
        let leftView = NSView(frame: NSRect(x: 0, y: 0, width: 300, height: content.bounds.height))
        scrollView.frame = NSRect(x: 0, y: 60, width: leftView.bounds.width, height: leftView.bounds.height - 60)
        scrollView.autoresizingMask = [.width, .height]
        leftView.addSubview(scrollView)

        // compact bottom-left toolbar (+ / -)
        addButton.title = "+"
        addButton.frame = NSRect(x: 12, y: 12, width: 28, height: 28)
        addButton.bezelStyle = .rounded
        addButton.target = self
        addButton.action = #selector(addConfig)
        leftView.addSubview(addButton)

        removeButton.title = "–"
        removeButton.frame = NSRect(x: 48, y: 12, width: 28, height: 28)
        removeButton.bezelStyle = .rounded
        removeButton.target = self
        removeButton.action = #selector(removeConfig)
        leftView.addSubview(removeButton)

        // right pane (details)
        let rightView = NSView(frame: NSRect(x: 0, y: 0, width: content.bounds.width - 300, height: content.bounds.height))
        let paneWidth = rightView.bounds.width - 40
        let paneHeight = rightView.bounds.height - 40
        let paneView = NSView(frame: NSRect(x: 20, y: 20, width: paneWidth, height: paneHeight))
        paneView.wantsLayer = true
        paneView.layer?.backgroundColor = NSColor(calibratedWhite: 0.13, alpha: 1.0).cgColor
        paneView.layer?.cornerRadius = 16.0
        paneView.layer?.masksToBounds = true
        rightView.addSubview(paneView)

        // Centered icon and title
        detailIconView.frame = NSRect(x: (paneWidth-56)/2, y: paneHeight-96, width: 56, height: 56)
        detailIconView.imageScaling = .scaleProportionallyUpOrDown
        detailIconView.contentTintColor = NSColor.systemBlue
        paneView.addSubview(detailIconView)

        detailTitleLabel.frame = NSRect(x: 0, y: paneHeight-140, width: paneWidth, height: 32)
        detailTitleLabel.font = NSFont.systemFont(ofSize: 20, weight: .bold)
        detailTitleLabel.textColor = NSColor.white
        detailTitleLabel.alignment = .center
        paneView.addSubview(detailTitleLabel)

        // Read-only fields with bold labels and light value text
        func makeLabel(_ text: String, y: CGFloat) -> NSTextField {
            let l = NSTextField(labelWithString: text)
            l.frame = NSRect(x: 40, y: y, width: 120, height: 20)
            l.font = NSFont.systemFont(ofSize: 13, weight: .semibold)
            l.textColor = NSColor(calibratedWhite: 0.85, alpha: 1.0)
            return l
        }
        func makeValueField(_ field: NSTextField, y: CGFloat) {
            field.frame = NSRect(x: 170, y: y, width: paneWidth-210, height: 20)
            field.isEditable = false
            field.isSelectable = true
            field.drawsBackground = false
            field.isBordered = false
            field.font = NSFont.systemFont(ofSize: 13, weight: .regular)
            field.textColor = NSColor(calibratedWhite: 0.98, alpha: 1.0)
            field.backgroundColor = NSColor.clear
            paneView.addSubview(field)
        }
        let rowYs: [CGFloat] = [paneHeight-190, paneHeight-230, paneHeight-270, paneHeight-310]
        let labels = ["Provider", "Client ID", "Client Secret", "OIDC URL"]
        let fields: [NSTextField] = [detailProviderField, detailClientIdField, detailClientSecretField, detailUrlField]
        for (i, label) in labels.enumerated() {
            paneView.addSubview(makeLabel(label, y: rowYs[i]))
            makeValueField(fields[i], y: rowYs[i])
        }

        // Edit button bottom right (toggles detail edit mode)
        editButton.frame = NSRect(x: paneWidth-100, y: 24, width: 80, height: 32)
        editButton.bezelStyle = .rounded
        editButton.title = "Edit"
        editButton.target = self
        editButton.action = #selector(editDetails)
        paneView.addSubview(editButton)

        // Save and Test buttons (hidden until editing)
        saveButton.frame = NSRect(x: paneWidth-260, y: 24, width: 90, height: 32)
        saveButton.bezelStyle = .rounded
        saveButton.title = "Save"
        saveButton.target = self
        saveButton.action = #selector(saveDetails)
        saveButton.isHidden = true
        paneView.addSubview(saveButton)

        testButton.frame = NSRect(x: paneWidth-360, y: 24, width: 90, height: 32)
        testButton.bezelStyle = .rounded
        testButton.title = "Test"
        testButton.target = self
        testButton.action = #selector(testConnection)
        testButton.isHidden = true
        paneView.addSubview(testButton)

        // (removed legacy rightView field code; all fields now use paneView layout above)
        splitView.addArrangedSubview(leftView)
        splitView.addArrangedSubview(rightView)
        splitView.setPosition(320, ofDividerAt: 0)
        content.addSubview(splitView)
    }

    public func numberOfRows(in tableView: NSTableView) -> Int { return configs.count }
    public func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        let config = configs[row]
        guard let ident = tableColumn?.identifier.rawValue else { return nil }
        if ident == "icon" {
            let iv = NSImageView(frame: NSRect(x: 6, y: 8, width: 32, height: 32))
            iv.imageScaling = .scaleProportionallyUpOrDown
            iv.image = iconForProvider(config.provider)
            // tint icon white when selected for contrast
            iv.contentTintColor = (tableView.selectedRow == row) ? NSColor.white : NSColor.systemBlue
            return iv
        }
        if ident == "status" {
            let dot = NSView(frame: NSRect(x: 3, y: 18, width: 12, height: 12))
            dot.wantsLayer = true
            dot.layer?.cornerRadius = 6
            dot.layer?.backgroundColor = NSColor.systemGreen.cgColor
            return dot
        }
        if ident == "provider" {
            let cell = NSTextField(labelWithString: config.provider)
            cell.lineBreakMode = .byTruncatingTail
            cell.font = NSFont.systemFont(ofSize: 14, weight: .medium)
            cell.textColor = (tableView.selectedRow == row) ? NSColor.white : NSColor(calibratedWhite: 0.95, alpha: 1.0)
            return cell
        }
        return nil
    }

    public func tableView(_ tableView: NSTableView, rowViewForRow row: Int) -> NSTableRowView? {
        return ProviderRowView()
    }

    private func iconForProvider(_ provider: String) -> NSImage? {
        let key = provider.lowercased()
        let symbol: String
        switch key {
        case "github": symbol = "person.crop.circle"
        case "google": symbol = "globe"
        case "microsoft": symbol = "desktopcomputer"
        case "apple": symbol = "applelogo"
        default: symbol = "network"
        }
        if #available(macOS 11.0, *) {
            return NSImage(systemSymbolName: symbol, accessibilityDescription: provider)
        }
        return nil
    }

    public func tableViewSelectionDidChange(_ notification: Notification) {
        let row = tableView.selectedRow
        if row >= 0 && row < configs.count {
            let config = configs[row]
            detailProviderField.stringValue = config.provider
            detailClientIdField.stringValue = config.clientId
            detailClientSecretField.stringValue = config.clientSecret
            detailUrlField.stringValue = config.oidcUrl
            detailTitleLabel.stringValue = config.provider
            detailIconView.image = iconForProvider(config.provider)
        } else {
            detailProviderField.stringValue = ""
            detailClientIdField.stringValue = ""
            detailClientSecretField.stringValue = ""
            detailUrlField.stringValue = ""
            detailTitleLabel.stringValue = ""
            detailIconView.image = nil
        }
        // refresh table so row views update their text/icon colors to match selection
        tableView.reloadData()
    }

    @objc private func addConfig() {
        let win = SettingsWindow(currentProvider: nil, currentClientId: nil, currentClientSecret: nil, currentUrl: nil) { [weak self] p, id, sec, url in
            guard let self = self else { return }
            let newConfig = ProviderConfig(provider: p, clientId: id, clientSecret: sec, oidcUrl: url)
            self.configs.append(newConfig)
            self.tableView.reloadData()
            self.onSave(self.configs)
        }
        win.runModal()
    }

    @objc private func editConfig() {
        let row = tableView.selectedRow
        guard row >= 0 else { return }
        let config = configs[row]
        let win = SettingsWindow(currentProvider: config.provider, currentClientId: config.clientId, currentClientSecret: config.clientSecret, currentUrl: config.oidcUrl) { [weak self] p, id, sec, url in
            guard let self = self else { return }
            self.configs[row] = ProviderConfig(provider: p, clientId: id, clientSecret: sec, oidcUrl: url)
            self.tableView.reloadData()
            self.onSave(self.configs)
        }
        win.runModal()
    }

    @objc private func removeConfig() {
        let row = tableView.selectedRow
        guard row >= 0 else { return }
        configs.remove(at: row)
        tableView.reloadData()
        onSave(configs)
    }

    @objc private func saveDetails() {
        let row = tableView.selectedRow
        guard row >= 0 else { return }
        let updated = ProviderConfig(provider: detailProviderField.stringValue, clientId: detailClientIdField.stringValue, clientSecret: detailClientSecretField.stringValue, oidcUrl: detailUrlField.stringValue)
        configs[row] = updated
        tableView.reloadData()
        onSave(configs)
        tableView.selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false)
        // exit edit mode
        detailProviderField.isEditable = false
        detailClientIdField.isEditable = false
        detailClientSecretField.isEditable = false
        detailUrlField.isEditable = false
        saveButton.isHidden = true
        testButton.isHidden = true
        editButton.isHidden = false
    }

    @objc private func testConnection() {
        let row = tableView.selectedRow
        guard row >= 0 else { return }
        let cfg = configs[row]
        // Placeholder for real connection test
        print("Testing OIDC connection for provider=\(cfg.provider) url=\(cfg.oidcUrl)")
    }

    @objc private func editDetails() {
        let row = tableView.selectedRow
        guard row >= 0 else { return }
        // enable editing of fields and show Save/Test buttons
        detailProviderField.isEditable = true
        detailClientIdField.isEditable = true
        detailClientSecretField.isEditable = true
        detailUrlField.isEditable = true
        saveButton.isHidden = false
        testButton.isHidden = false
        editButton.isHidden = true
    }

    public func runModal() {
        let app = NSApplication.shared
        app.activate(ignoringOtherApps: true)
        app.runModal(for: self)
    }

    public func windowWillClose(_ notification: Notification) {
        NSApp.stopModal()
    }
}
