// SSHKeygen.swift
// Utilities for generating SSH key pairs and OpenPubkey certificates in memory
// macOS only

import Foundation
import CryptoKit

public class SSHKeygen {
    public static func generateEd25519KeyPair() -> (privateKey: Data, publicKey: Data)? {
        if #available(macOS 10.15, *) {
            let privateKey = Curve25519.Signing.PrivateKey()
            let publicKey = privateKey.publicKey.rawRepresentation
            return (privateKey: privateKey.rawRepresentation, publicKey: publicKey)
        } else {
            return nil
        }
    }

    public static func generateOpenPubkeyCertificate(publicKey: Data, oidcToken: String) -> Data? {
        return nil
    }
}
