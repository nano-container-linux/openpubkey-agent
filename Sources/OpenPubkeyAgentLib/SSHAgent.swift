// SSHAgent.swift
// Minimal SSH agent for OpenPubkey, in-memory only (no disk storage)
// macOS only

import Foundation
import CryptoKit

public class SSHAgent {
    private let socketPath: String
    private var listener: FileHandle?
    private var privateKey: Data? // In-memory private key
    private var certificate: Data? // In-memory SSH certificate
    private var publicKey: Data?
    private var keyComment: String?

    public init(socketPath: String = "/tmp/openpubkey-agent.sock") {
        self.socketPath = socketPath
    }

    public func start() throws {
        // Remove any existing socket
        unlink(socketPath)
        // Create Unix domain socket
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw NSError(domain: "SSHAgent", code: 1, userInfo: [NSLocalizedDescriptionKey: "Failed to create socket"]) }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        // copy path into sun_path safely
        let pathCString = socketPath.utf8CString
        let pathData = Data(pathCString.map { UInt8(bitPattern: $0) })
        withUnsafeMutableBytes(of: &addr.sun_path) { dest in
            let copyCount = min(dest.count, pathData.count)
            pathData.withUnsafeBytes { src in
                if let srcBase = src.baseAddress, let destBase = dest.baseAddress {
                    destBase.copyMemory(from: srcBase, byteCount: copyCount)
                }
            }
        }
        let len = socklen_t(MemoryLayout.size(ofValue: addr))
        let bindResult = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, len)
            }
        }
        guard bindResult == 0 else { throw NSError(domain: "SSHAgent", code: 2, userInfo: [NSLocalizedDescriptionKey: "Failed to bind socket"]) }
        listen(fd, 5)
        listener = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        DispatchQueue.global().async { [weak self] in self?.acceptLoop() }
        // Export SSH_AUTH_SOCK
        setenv("SSH_AUTH_SOCK", socketPath, 1)
        print("[OpenPubkeyAgent] SSH agent socket path: \(socketPath)")
    }

    private func acceptLoop() {
        guard let listener = listener else { return }
        while true {
            let clientFd = accept(listener.fileDescriptor, nil, nil)
            if clientFd >= 0 {
                DispatchQueue.global().async {
                    self.handleClient(fd: clientFd)
                }
            }
        }
    }

    private func handleClient(fd: Int32) {
        // Handle multiple agent messages on this connection.
        let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer { file.closeFile() }

        // Debug logging (set environment var OPENPUBKEY_AGENT_DEBUG=1 to enable)
        let debugEnabled = getenv("OPENPUBKEY_AGENT_DEBUG") != nil
        func hexdump(_ d: Data) -> String {
              let max = 128
              let prefix = d.prefix(max)
              let s = prefix.map { String(format: "%02x", $0) }.joined()
              return prefix.count == d.count ? s : s + "..."
        }
        func writeOut(_ d: Data) {
            if debugEnabled {
                if d.count >= 4 {
                    // show length + payload
                    let l = Int(d[0]) << 24 | Int(d[1]) << 16 | Int(d[2]) << 8 | Int(d[3])
                    print("[OpenPubkeyAgent][TX] len=\(l) total=\(d.count) bytes payload=\(hexdump(d.suffix(from: 4)))")
                } else {
                    print("[OpenPubkeyAgent][TX] total=\(d.count) bytes payload=\(hexdump(d))")
                }
            }
            file.write(d)
        }

        func readUint32(from data: Data, at idx: inout Int) -> UInt32? {
            guard idx + 4 <= data.count else { return nil }
            let b0 = UInt32(data[idx])
            let b1 = UInt32(data[idx+1])
            let b2 = UInt32(data[idx+2])
            let b3 = UInt32(data[idx+3])
            idx += 4
            return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
        }

        func readString(from data: Data, at idx: inout Int) -> Data? {
            guard let l = readUint32(from: data, at: &idx) else { return nil }
            let len = Int(l)
            guard idx + len <= data.count else { return nil }
            let s = data[idx..<(idx+len)]
            idx += len
            return Data(s)
        }

        while true {
            // Read length
            let lenData = file.readData(ofLength: 4)
            if lenData.count == 0 { return } // EOF
            guard lenData.count == 4 else { return }
            let msgLen = UInt32(lenData[0]) << 24 | UInt32(lenData[1]) << 16 | UInt32(lenData[2]) << 8 | UInt32(lenData[3])
            let msgData = file.readData(ofLength: Int(msgLen))
            guard msgData.count == msgLen else { return }
            if debugEnabled {
                print("[OpenPubkeyAgent][RX] len=\(msgLen) total=\(4 + msgData.count) bytes payload=\(hexdump(msgData))")
            }
            var idx = 0
            guard let msgType = msgData.first else { return }

            switch msgType {
            case 11: // SSH2_AGENTC_REQUEST_IDENTITIES
                var resp = Data([12]) // SSH2_AGENT_IDENTITIES_ANSWER
                // Build list: include any plain public key added via ssh-add, then any certificate
                var identities: [(Data, String)] = []
                if let pk = publicKey {
                    identities.append((pk, keyComment ?? "openpubkey-key"))
                }
                if let cert = certificate {
                    identities.append((cert, "openpubkey-agent"))
                }
                resp.append(UInt32(UInt32(identities.count)).bigEndianData)
                for (blob, comment) in identities {
                    // Ensure identity blob for plain keys is the SSH wire-format (type + keydata)
                    var identityBlob = blob
                    if let pk = publicKey, blob == pk {
                        // construct ssh-ed25519 public key blob
                        var b = Data()
                        b.append(sshString(Data("ssh-ed25519".utf8)))
                        b.append(sshString(pk))
                        identityBlob = b
                    }
                    resp.append(sshString(identityBlob))
                    resp.append(sshString(comment))
                }
                var out = UInt32(resp.count).bigEndianData
                out.append(resp)
                writeOut(out)

            case 13: // SSH2_AGENTC_SIGN_REQUEST
                // message: byte type; string key_blob; string data; uint32 flags
                idx = 1
                guard let keyBlob = readString(from: msgData, at: &idx) else { break }
                guard let dataToSign = readString(from: msgData, at: &idx) else { break }
                guard let _ = readUint32(from: msgData, at: &idx) else { break } // flags

                // Extract public key from keyBlob. Accept either a plain
                // `ssh-ed25519` key blob or a certificate blob
                var keyIdx = 0
                guard let alg = readString(from: keyBlob, at: &keyIdx), let _ = String(data: alg, encoding: .utf8) else { break }

                // Helper to extract the inner ed25519 public key from a
                // certificate blob (or from a plain key blob). Returns the
                // 32-byte raw public key if found.
                func extractEd25519Pub(from blob: Data) -> Data? {
                    var idxLocal = 0
                    guard let topLen = readUint32(from: blob, at: &idxLocal) else { return nil }
                    guard idxLocal + Int(topLen) <= blob.count else { return nil }
                    let typeData = blob[idxLocal..<(idxLocal + Int(topLen))]
                    if let typeStr = String(data: Data(typeData), encoding: .utf8) {
                        if typeStr == SSH_KEY_TYPE_ED25519 {
                            var pidx = 0
                            if let _ = readString(from: blob, at: &pidx), let pub = readString(from: blob, at: &pidx) {
                                return pub
                            }
                            return nil
                        }
                        if typeStr == SSH_CERT_TYPE_ED25519 {
                            idxLocal += Int(topLen)
                            guard let _ = readString(from: blob, at: &idxLocal) else { return nil }
                            guard let pubField = readString(from: blob, at: &idxLocal) else { return nil }
                            var pfIdx = 0
                            guard let innerType = readString(from: pubField, at: &pfIdx), let innerTypeStr = String(data: innerType, encoding: .utf8), innerTypeStr == SSH_KEY_TYPE_ED25519 else { return nil }
                            return readString(from: pubField, at: &pfIdx)
                        }
                    }
                    return nil
                }

                let pubkey = extractEd25519Pub(from: keyBlob)

                if let pub = pubkey, let priv = privateKey {
                    #if canImport(CryptoKit)
                    if let pk = try? Curve25519.Signing.PrivateKey(rawRepresentation: priv) {
                        if let sig = try? pk.signature(for: dataToSign) {
                            var resp = Data([14])
                            var sigBlob = Data()
                            sigBlob.append(sshString(Data("ssh-ed25519".utf8)))
                            sigBlob.append(sshString(sig))
                            resp.append(sshString(sigBlob))
                            var out = UInt32(resp.count).bigEndianData
                            out.append(resp)
                            writeOut(out)
                            break
                        }
                    }
                    #endif
                }
                let fail = Data([UInt8(5)])
                var fout = UInt32(fail.count).bigEndianData
                fout.append(fail)
                writeOut(fout)

            case 17: // SSH2_AGENTC_ADD_IDENTITY
                idx = 1
                guard let keyTypeData = readString(from: msgData, at: &idx), let keyType = String(data: keyTypeData, encoding: .utf8) else { break }
                if keyType == "ssh-ed25519" {
                    guard let pub = readString(from: msgData, at: &idx) else { break }
                    guard let priv = readString(from: msgData, at: &idx) else { break }
                    guard let commentData = readString(from: msgData, at: &idx), let comment = String(data: commentData, encoding: .utf8) else { break }
                    if debugEnabled {
                        print("[OpenPubkeyAgent][ADD_IDENTITY] keyType=ssh-ed25519 pub.len=\(pub.count) priv.len=\(priv.count) comment=\(comment)")
                    }
                    self.publicKey = pub
                    self.privateKey = priv
                    self.keyComment = comment
                    let ok = Data([UInt8(6)])
                    var okout = UInt32(ok.count).bigEndianData
                    okout.append(ok)
                    writeOut(okout)
                    break
                } else if keyType == SSH_CERT_TYPE_ED25519 {
                    guard let pub = readString(from: msgData, at: &idx) else { break }
                    guard let priv = readString(from: msgData, at: &idx) else { break }
                    guard let commentData = readString(from: msgData, at: &idx), let comment = String(data: commentData, encoding: .utf8) else { break }
                    if debugEnabled {
                        print("[OpenPubkeyAgent][ADD_IDENTITY] keyType=\(SSH_CERT_TYPE_ED25519) pub.len=\(pub.count) priv.len=\(priv.count) comment=\(comment)")
                    }
                    self.certificate = pub
                    self.privateKey = priv
                    self.keyComment = comment
                    func extractFromCert(_ blob: Data) -> Data? {
                        var i = 0
                        if let topLen = readUint32(from: blob, at: &i) {
                            if i + Int(topLen) <= blob.count {
                                let typeData = blob[i..<(i+Int(topLen))]
                                if let typeStr = String(data: Data(typeData), encoding: .utf8), typeStr == SSH_CERT_TYPE_ED25519 {
                                    i += Int(topLen)
                                } else { i = 0 }
                            } else { return nil }
                        }
                        guard let _ = readString(from: blob, at: &i) else { return nil }
                        guard let pubField = readString(from: blob, at: &i) else { return nil }
                        var pfIdx = 0
                        guard let innerType = readString(from: pubField, at: &pfIdx), let innerTypeStr = String(data: innerType, encoding: .utf8), innerTypeStr == "ssh-ed25519" else { return nil }
                        return readString(from: pubField, at: &pfIdx)
                    }
                    if let inner = extractFromCert(pub) { self.publicKey = inner }
                    let ok = Data([UInt8(6)])
                    var okout = UInt32(ok.count).bigEndianData
                    okout.append(ok)
                    writeOut(okout)
                    break
                } else {
                    let fail = Data([UInt8(5)])
                    var fout = UInt32(fail.count).bigEndianData
                    fout.append(fail)
                    writeOut(fout)
                    break
                }

            default:
                var fail = Data([UInt8(5)])
                var fout = UInt32(fail.count).bigEndianData
                fout.append(fail)
                writeOut(fout)
            }
        }
    }

    private func sshString(_ d: Data) -> Data {
        var out = Data()
        out.append(UInt32(d.count).bigEndianData)
        out.append(d)
        return out
    }
    private func sshString(_ s: String) -> Data {
        let strData = s.data(using: .utf8) ?? Data()
        return sshString(strData)
    }

    public func setKeyAndCert(privateKey: Data, certificate: Data) {
        self.privateKey = privateKey
        self.certificate = certificate
    }

    public func setPrivatePublic(privateKey: Data, publicKey: Data, comment: String? = nil) {
        self.privateKey = privateKey
        self.publicKey = publicKey
        self.keyComment = comment
    }
}
