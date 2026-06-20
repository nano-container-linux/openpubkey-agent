import Foundation

public let SSH_CERT_TYPE_ED25519 = "ssh-ed25519-cert-v01@openssh.com"
public let SSH_KEY_TYPE_ED25519 = "ssh-ed25519"

public struct SSHEd25519Cert {
    public var nonce: Data
    public var publicKey: Data
    public var serial: UInt64
    public var certType: UInt32 // 1 = user, 2 = host
    public var keyId: String
    public var validPrincipals: [String]
    public var validAfter: UInt64
    public var validBefore: UInt64
    public var criticalOptions: [String: String]
    public var extensions: [String: String]
    public var signatureKey: Data
    public var signature: Data

    public static func createSignedCert(
        publicKey: Data,
        keyId: String,
        validPrincipals: [String],
        validAfter: UInt64,
        validBefore: UInt64,
        extensions: [String: String],
        ca: SSHCA,
        debugFixedFields: [String: Data]? = nil
    ) -> SSHEd25519Cert {
        let nonce = debugFixedFields?[
            "nonce"] ?? Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let pubKey = debugFixedFields?["publicKey"] ?? publicKey
        let serial: UInt64 = debugFixedFields?["serial"].flatMap { Data($0).withUnsafeBytes { UInt64(bigEndian: $0.load(as: UInt64.self)) } } ?? UInt64.random(in: 1...UInt64.max)
        let certType: UInt32 = 1
        let keyIdStr = debugFixedFields?["keyId"].flatMap { String(data: $0, encoding: .utf8) } ?? keyId
        let principals = debugFixedFields?["validPrincipals"].flatMap { [$0].compactMap { String(data: $0, encoding: .utf8) } } ?? validPrincipals
        let validAfterVal: UInt64 = debugFixedFields?["validAfter"].flatMap { Data($0).withUnsafeBytes { UInt64(bigEndian: $0.load(as: UInt64.self)) } } ?? validAfter
        let validBeforeVal: UInt64 = debugFixedFields?["validBefore"].flatMap { Data($0).withUnsafeBytes { UInt64(bigEndian: $0.load(as: UInt64.self)) } } ?? validBefore
        let criticalOptions: [String: String] = [:]
        let signatureKey = debugFixedFields?["signatureKey"] ?? ca.publicKey

        var fullExtensions: [String: String] = [
            "permit-X11-forwarding": "",
            "permit-agent-forwarding": "",
            "permit-port-forwarding": "",
            "permit-pty": "",
            "permit-user-rc": ""
        ]
        for (k, v) in extensions { fullExtensions[k] = v }

        var cert = SSHEd25519Cert(
            nonce: nonce,
            publicKey: pubKey,
            serial: serial,
            certType: certType,
            keyId: keyIdStr,
            validPrincipals: principals,
            validAfter: validAfterVal,
            validBefore: validBeforeVal,
            criticalOptions: criticalOptions,
            extensions: fullExtensions,
            signatureKey: signatureKey,
            signature: Data()
        )

        // OpenSSH signs the certificate over the top-level type string followed
        // by the certificate content (i.e. ssh-string(type) || content).
        var toSign = Data()
        // build ssh-string(type) bytes manually (static context)
        if let typeData = SSH_CERT_TYPE_ED25519.data(using: .utf8) {
            var len = UInt32(typeData.count).bigEndian
            withUnsafeBytes(of: &len) { toSign.append(contentsOf: $0) }
            toSign.append(typeData)
        }
        toSign.append(cert.serializeContent(includeSignature: false))
        let sig = ca.sign(toSign)
        cert.signature = sig
        return cert
    }

    private func serializeContent(includeSignature: Bool = true) -> Data {
        var content = Data()
        content.append(sshString(nonce))
        // For ed25519 certs the public key field is an inner blob: ssh-string(keytype) + ssh-string(32-byte-key)
        // For ed25519 in the certificate the public key is encoded as a raw
        // 32-byte string (ssh-string of the keydata) — do not include an inner
        // key-type string here.
        content.append(sshString(publicKey.prefix(32)))
        content.append(serial.bigEndianData)
        content.append(certType.bigEndianData)
        content.append(sshString(keyId))
        var principalsData = Data()
        for p in validPrincipals { principalsData.append(sshString(p)) }
        content.append(sshString(principalsData))
        content.append(validAfter.bigEndianData)
        content.append(validBefore.bigEndianData)
        content.append(sshDictSorted(criticalOptions))
        content.append(sshDictSorted(extensions))
        content.append(UInt32(0).bigEndianData)
        // signatureKey is encoded as an ssh-string containing the key blob.
        // Encode signatureKey as inner blob: ssh-string(type) + ssh-string(keydata)
        var sigKeyField = Data()
        sigKeyField.append(sshString(SSH_KEY_TYPE_ED25519))
        sigKeyField.append(sshString(signatureKey.prefix(32)))
        content.append(sshString(sigKeyField))
        if includeSignature {
            var sigField = Data()
            sigField.append(sshString(SSH_KEY_TYPE_ED25519))
            sigField.append(sshString(signature))
            content.append(sshString(sigField))
        }
        return content
    }

    public func serialize(includeSignature: Bool = true) -> Data {
        let content = serializeContent(includeSignature: includeSignature)
        // debug print removed for cleaner output
        var out = Data()
        out.append(sshString(SSH_CERT_TYPE_ED25519))
        // OpenSSH certificate blob format: top-level is ssh-string(type) immediately followed by
        // the raw certificate content (no extra ssh-string wrapper around the content).
        out.append(content)
        return out
    }

    public func serializeAsOpenSSHLine(comment: String) -> String {
        let blob = serialize(includeSignature: true)
        let b64 = blob.base64EncodedString()
        return "\(SSH_CERT_TYPE_ED25519) \(b64) \(comment)\n"
    }

    public func debugSummary() -> String {
        let contentNoSig = serializeContent(includeSignature: false)
        let contentWithSig = serializeContent(includeSignature: true)
        var s = "contentNoSig.len=\(contentNoSig.count) contentWithSig.len=\(contentWithSig.count)\n"
        s += "nonce.len=32 pubkey.len=\(publicKey.prefix(32).count) serial=\(serial) sigKey.len=\(signatureKey.count) sig.len=\(signature.count)\n"
        s += "first32(contentNoSig)=\(contentNoSig.prefix(32).map { String(format: "%02x", $0) }.joined())\n"
        s += "first32(contentWithSig)=\(contentWithSig.prefix(32).map { String(format: "%02x", $0) }.joined())\n"
        return s
    }

    // Expose serialized certificate content (without top-level type) for debugging.
    public func serializedContentNoType(includeSignature: Bool = true) -> Data {
        return serializeContent(includeSignature: includeSignature)
    }

    private func sshString(_ s: String) -> Data {
        let d = s.data(using: .utf8) ?? Data()
        return sshString(d)
    }
    private func sshString(_ d: Data) -> Data {
        var out = Data()
        out.append(UInt32(d.count).bigEndianData)
        out.append(d)
        return out
    }
    private func sshDictSorted(_ dict: [String: String]) -> Data {
        var d = Data()
        let preferredOrder = [
            "permit-X11-forwarding",
            "permit-agent-forwarding",
            "permit-port-forwarding",
            "permit-pty",
            "permit-user-rc"
        ]
        var seen = Set<String>()
        for k in preferredOrder {
            if let v = dict[k] {
                d.append(sshString(k))
                d.append(sshString(v))
                seen.insert(k)
            }
        }
        for (k, v) in dict.filter({ !seen.contains($0.key) }).sorted(by: { $0.key < $1.key }) {
            d.append(sshString(k))
            d.append(sshString(v))
        }
        return sshString(d)
    }
}

extension UInt32 {
    public var bigEndianData: Data {
        let be = self.bigEndian
        return withUnsafeBytes(of: be) { Data($0) }
    }
}

extension UInt64 {
    public var bigEndianData: Data {
        let be = self.bigEndian
        return withUnsafeBytes(of: be) { Data($0) }
    }
}
