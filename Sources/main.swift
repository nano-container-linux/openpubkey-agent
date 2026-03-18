//
//  main.swift
//  OpenPubkeyAgent
//
//  macOS application for automatic renewal of OpenPubkey SSH certificates.
//

import Cocoa

class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        let auth = OIDCAuth()
        auth.requestPassword { password in
            if let pwd = password {
                print("OIDC password entered: \(pwd)")
                // Here, add the real OIDC authentication logic
            } else {
                print("No password entered.")
            }
            NSApp.terminate(nil)
        }
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
