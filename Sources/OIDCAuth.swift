// OIDCAuth.swift
// OIDC authentication management for OpenPubkeyAgent

import Cocoa

class OIDCAuth {
    func requestPassword(completion: @escaping (String?) -> Void) {
        DispatchQueue.main.async {
            let prompt = OIDCPasswordPrompt(window: nil)
            prompt.showWindow(nil)
            prompt.runModal { password in
                completion(password)
            }
        }
    }
}
