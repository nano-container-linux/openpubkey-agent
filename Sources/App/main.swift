//
//  main.swift
//  OpenPubkeyAgent
//
//  macOS application for automatic renewal of OpenPubkey SSH certificates.
//

import Cocoa
import Foundation
import OpenPubkeyAgent


class AppDelegate: NSObject, NSApplicationDelegate {
    var statusItem: NSStatusItem?
    var lastRenewal: Date?
    var nextRenewal: Date?
    var providerConfigs: [ProviderConfig] = []
    let settingsConfigsKey = "opk_providerConfigs"
    var sshAgent: SSHAgent?

    func applicationDidFinishLaunching(_ notification: Notification) {
        let defaults = UserDefaults.standard
        if let data = defaults.data(forKey: settingsConfigsKey),
           let configs = try? JSONDecoder().decode([ProviderConfig].self, from: data) {
            providerConfigs = configs
        }
        lastRenewal = Date()
        nextRenewal = Calendar.current.date(byAdding: .hour, value: 8, to: lastRenewal!)

        let agent = SSHAgent()
        do {
            try agent.start()
            self.sshAgent = agent
        } catch {
            print("Failed to start SSH agent: \(error)")
        }

        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
            self.loginAndLoadSSHKey()
        }

        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        if let button = statusItem?.button {
            button.image = NSImage(named: NSImage.Name("NSLockLockedTemplate"))
            button.toolTip = "OpenPubkeyAgent"
        }

        let menu = NSMenu()
        let dateFormatter = DateFormatter()
        dateFormatter.dateStyle = .medium
        dateFormatter.timeStyle = .medium

        let sectionLabel = NSMenuItem()
        sectionLabel.title = "SSH Certificate Renewals"
        sectionLabel.isEnabled = false
        menu.addItem(sectionLabel)

        let lastLabel = "Last: " + (lastRenewal != nil ? dateFormatter.string(from: lastRenewal!) : "-")
        let nextLabel = "Next: " + (nextRenewal != nil ? dateFormatter.string(from: nextRenewal!) : "-")

        menu.addItem(withTitle: lastLabel, action: nil, keyEquivalent: "")
        menu.addItem(withTitle: nextLabel, action: nil, keyEquivalent: "")
        menu.addItem(NSMenuItem.separator())
        menu.addItem(withTitle: "Login & Load SSH Key", action: #selector(loginAndLoadSSHKey), keyEquivalent: "l")
        menu.addItem(withTitle: "Manage Providers & Keys", action: #selector(openSettingsManager), keyEquivalent: ",")
        menu.addItem(withTitle: "Quit", action: #selector(quit), keyEquivalent: "q")

        statusItem?.menu = menu
    }

    @objc func loginAndLoadSSHKey() {
        guard let config = providerConfigs.first else {
            print("No OIDC provider configured.")
            return
        }
        let oidcToken = "FAKE_OIDC_TOKEN"
        guard let (priv, pub) = SSHKeygen.generateEd25519KeyPair() else {
            print("Failed to generate SSH key pair.")
            return
        }
        let ca = SSHCA()
        let certObj = SSHEd25519Cert.createSignedCert(
            publicKey: pub,
            keyId: "test_identity",
            validPrincipals: ["testuser"],
            validAfter: 0,
            validBefore: UInt64.max,
            extensions: ["openpubkey-pktoken": oidcToken],
            ca: ca
        )
        let cert = certObj.serialize()
        func sshString(_ d: Data) -> Data {
            var out = Data()
            out.append(UInt32(d.count).bigEndianData)
            out.append(d)
            return out
        }
        let certSSHString = sshString(cert)
        let certB64 = cert.base64EncodedString()
        print("[DEBUG] SSH cert blob (base64):\n\(certB64)")
        let debugURL = URL(fileURLWithPath: "cert_swift.bin", isDirectory: false)
        do {
            try certSSHString.write(to: debugURL)
            print("[DEBUG] Wrote SSH string-wrapped cert to cert_swift.bin")
        } catch {
            print("[DEBUG] Failed to write cert_swift.bin: \(error)")
        }
        setKeyAndCert(privateKey: priv, certificate: cert)
        print("SSH key and OpenPubkey cert loaded in agent (memory only)")
    }

    @objc func openSettingsManager() {
        let managerWindow = SettingsManagerWindow(configs: providerConfigs) { [weak self] newConfigs in
            guard let self = self else { return }
            self.providerConfigs = newConfigs
            if let data = try? JSONEncoder().encode(newConfigs) {
                UserDefaults.standard.set(data, forKey: self.settingsConfigsKey)
            }
        }
        managerWindow.runModal()
    }

    func setKeyAndCert(privateKey: Data, certificate: Data) {
        sshAgent?.setKeyAndCert(privateKey: privateKey, certificate: certificate)
    }

    @objc func quit() {
        NSApp.terminate(nil)
    }
}


let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
