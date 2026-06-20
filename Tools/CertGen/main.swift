import Foundation
import OpenPubkeyAgent

let fm = FileManager.default
let tmp = fm.currentDirectoryPath + "/tmp"
try? fm.createDirectory(atPath: tmp, withIntermediateDirectories: true)

// Generate keypair
guard let (priv, pub) = SSHKeygen.generateEd25519KeyPair() else {
    print("failed to generate keypair")
    exit(1)
}

let ca = SSHCA()

// non-deterministic cert
let cert = SSHEd25519Cert.createSignedCert(publicKey: pub, keyId: "test-key", validPrincipals: ["testuser"], validAfter: 0, validBefore: UInt64(1<<62), extensions: [:], ca: ca)
let certBlob = cert.serialize()
let ourPath = tmp + "/our-cert.bin"
try certBlob.write(to: URL(fileURLWithPath: ourPath))
print("wrote our cert: \(ourPath) size=\(certBlob.count)")

// deterministic cert using fixed debug fields
var debugFixed = [String: Data]()
debugFixed["nonce"] = Data(repeating: 0x42, count: 32)
debugFixed["publicKey"] = pub
// Match canonical ssh-keygen-generated cert fields for easier diffing
let serialBE: UInt64 = 0
debugFixed["serial"] = withUnsafeBytes(of: serialBE.bigEndian) { Data($0) }
debugFixed["keyId"] = "testid".data(using: .utf8)
debugFixed["validPrincipals"] = "testuser".data(using: .utf8)
// canonical ssh-keygen example uses these timestamps
let validAfterBE: UInt64 = 1774197120
debugFixed["validAfter"] = withUnsafeBytes(of: validAfterBE.bigEndian) { Data($0) }
let validBeforeBE: UInt64 = 1805646818
debugFixed["validBefore"] = withUnsafeBytes(of: validBeforeBE.bigEndian) { Data($0) }

let certDet = SSHEd25519Cert.createSignedCert(publicKey: pub, keyId: "test-key", validPrincipals: ["testuser"], validAfter: 0, validBefore: UInt64(1<<62), extensions: [:], ca: ca, debugFixedFields: debugFixed)
let refPath = tmp + "/ref-cert.bin"
try certDet.serialize().write(to: URL(fileURLWithPath: refPath))
print("wrote ref cert: \(refPath) size=\(certDet.serialize().count)")


let contentNoSig = certDet.serializedContentNoType(includeSignature: false)
// Build signing input as ssh-string(type) || content (matches createSignedCert)
var signingInput = Data()
if let typeData = SSH_CERT_TYPE_ED25519.data(using: .utf8) {
    signingInput.append(UInt32(typeData.count).bigEndianData)
    signingInput.append(typeData)
}
signingInput.append(contentNoSig)
let hex = contentNoSig.map { String(format: "%02x", $0) }.joined()
// minimal output
print("wrote ref cert: \(refPath) size=\(certDet.serialize().count)")

#if canImport(CryptoKit)
import CryptoKit
    if let pubk = try? Curve25519.Signing.PublicKey(rawRepresentation: ca.publicKey) {
    let ok = pubk.isValidSignature(certDet.signature, for: signingInput)
    print("local signature verify=\(ok)")
} else {
    print("cannot construct public key for verify")
}
#endif
