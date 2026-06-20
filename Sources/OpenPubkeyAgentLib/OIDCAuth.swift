// OIDCAuth.swift
// OIDC authentication management for OpenPubkeyAgent

import Cocoa

public class OIDCAuth {
    public init() {}
    public func requestPassword(completion: @escaping (String?) -> Void) {
        DispatchQueue.main.async {
            let prompt = OIDCPasswordPrompt()
            prompt.runModal { password in
                completion(password)
            }
        }
    }
}
