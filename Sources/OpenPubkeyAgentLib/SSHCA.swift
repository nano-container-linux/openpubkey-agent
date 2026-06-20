// SSHCA.swift
// Simple Ed25519 CA for signing SSH certificates (test only)
// macOS only


import Foundation
import CryptoKit


public class SSHCA {
    let privateKey: Curve25519.Signing.PrivateKey
    public let publicKey: Data

    static let caKeyPath: URL = {
        let dir = FileManager.default.homeDirectoryForCurrentUser
        return dir.appendingPathComponent(".openpubkey-ca.key")
    }()

    public init() {
        if let keyData = try? Data(contentsOf: SSHCA.caKeyPath), keyData.count == 64 {
            self.privateKey = try! Curve25519.Signing.PrivateKey(rawRepresentation: keyData)
        } else {
            let priv = Curve25519.Signing.PrivateKey()
            try? priv.rawRepresentation.write(to: SSHCA.caKeyPath, options: [.atomic, .completeFileProtection])
            self.privateKey = priv
        }
        self.publicKey = privateKey.publicKey.rawRepresentation
    }

    public func sign(_ data: Data) -> Data {
        let signature = try! privateKey.signature(for: data)
        return signature
    }
}
