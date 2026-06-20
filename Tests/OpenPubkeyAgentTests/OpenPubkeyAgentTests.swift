import XCTest
import Foundation
@testable import OpenPubkeyAgent

final class OpenPubkeyAgentTests: XCTestCase {
    func runCommand(_ cmd: String, args: [String]) -> (Int32, String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: cmd)
        p.arguments = args
        let outPipe = Pipe()
        p.standardOutput = outPipe
        p.standardError = outPipe
        try! p.run()
        p.waitUntilExit()
        let data = outPipe.fileHandleForReading.readDataToEndOfFile()
        let s = String(data: data, encoding: .utf8) ?? ""
        return (p.terminationStatus, s)
    }

    func runCommandEnv(_ cmd: String, args: [String], env: [String: String]) -> (Int32, String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: cmd)
        p.arguments = args
        var merged = ProcessInfo.processInfo.environment
        for (k, v) in env { merged[k] = v }
        p.environment = merged
        let outPipe = Pipe()
        p.standardOutput = outPipe
        p.standardError = outPipe
        try! p.run()
        p.waitUntilExit()
        let data = outPipe.fileHandleForReading.readDataToEndOfFile()
        let s = String(data: data, encoding: .utf8) ?? ""
        return (p.terminationStatus, s)
    }

    func testCertificateFormatAcceptedBySshKeygen() throws {
        // Delegate the E2E flow to a shell script to avoid running ssh-agent inside XCTest.
        let repoRoot = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        let script = repoRoot.appendingPathComponent("Tools/e2e/run_e2e.sh")
        let (rc, out) = runCommand("/bin/bash", args: ["-c", script.path])
        print("run_e2e.sh rc=\(rc) output:\n\(out)")
        XCTAssertEqual(rc, 0, "E2E script failed: \(out)")
    }

    func testAgentRequestIdentitiesAndSign() throws {
        let fm = FileManager.default
        let tmp = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try fm.createDirectory(at: tmp, withIntermediateDirectories: true)

        let socketPath = tmp.appendingPathComponent("agent.sock").path
        let agent = SSHAgent(socketPath: socketPath)
        try agent.start()

        // Generate ed25519 keypair using CryptoKit helper
        guard let (priv, pub) = SSHKeygen.generateEd25519KeyPair() else {
            XCTFail("could not generate keypair")
            return
        }
        // Inject key into agent
        agent.setPrivatePublic(privateKey: priv, publicKey: pub, comment: "test-comment")

        // Connect to agent socket
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        XCTAssertTrue(fd >= 0)
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
        let addrLen = socklen_t(MemoryLayout.size(ofValue: addr))
        let res = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sp in
                connect(fd, sp, addrLen)
            }
        }
        XCTAssertEqual(res, 0, "connect failed")

        func writeAll(_ fd: Int32, _ d: Data) {
            d.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) in
                var off = 0
                while off < d.count {
                    let w = write(fd, ptr.baseAddress!.advanced(by: off), d.count - off)
                    if w <= 0 { break }
                    off += w
                }
            }
        }

        func readN(_ fd: Int32, _ n: Int) -> Data {
            var buf = [UInt8](repeating: 0, count: n)
            var got = 0
            while got < n {
                let remaining = n - got
                let readCount = buf.withUnsafeMutableBytes { (ptr: UnsafeMutableRawBufferPointer) -> Int in
                    let base = ptr.baseAddress!.advanced(by: got)
                    let r = read(fd, base, remaining)
                    return r
                }
                if readCount <= 0 { break }
                got += readCount
            }
            return Data(buf[0..<got])
        }

        // Helper to build ssh-string
        func sshString(_ d: Data) -> Data {
            var out = Data()
            out.append(UInt32(d.count).bigEndianData)
            out.append(d)
            return out
        }

        // Send REQUEST_IDENTITIES (11)
        var req = Data()
        req.append(UInt8(11))
        var msg = UInt32(req.count).bigEndianData
        msg.append(req)
        writeAll(fd, msg)

        // Read response length
        var lenBuf = [UInt8](repeating: 0, count: 4)
        _ = read(fd, &lenBuf, 4)
        let respLen = (UInt32(lenBuf[0]) << 24) | (UInt32(lenBuf[1]) << 16) | (UInt32(lenBuf[2]) << 8) | UInt32(lenBuf[3])
        let resp = readN(fd, Int(respLen))
        XCTAssertEqual(resp.first, 12, "expected identities answer")

        // Now test SIGN_REQUEST (13)
        // key blob: string("ssh-ed25519") + string(pub)
        var keyInner = Data()
        keyInner.append(sshString(Data("ssh-ed25519".utf8)))
        keyInner.append(sshString(pub))
        let keyBlob = sshString(keyInner)
        let dataToSign = "hello".data(using: .utf8)!
        var signReq = Data()
        signReq.append(UInt8(13))
        signReq.append(keyBlob)
        signReq.append(sshString(dataToSign))
        signReq.append(UInt32(0).bigEndianData) // flags
        var signMsg = UInt32(signReq.count).bigEndianData
        signMsg.append(signReq)
        writeAll(fd, signMsg)

        // Read sign response
        _ = read(fd, &lenBuf, 4)
        let sLen = (UInt32(lenBuf[0]) << 24) | (UInt32(lenBuf[1]) << 16) | (UInt32(lenBuf[2]) << 8) | UInt32(lenBuf[3])
        let sResp = readN(fd, Int(sLen))
        XCTAssertEqual(sResp.first, 14, "expected sign response")

        close(fd)
    }

    func testAgentWorksWithSshAdd() throws {
        let fm = FileManager.default
        let tmp = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try fm.createDirectory(at: tmp, withIntermediateDirectories: true)

        let socketPath = tmp.appendingPathComponent("agent.sock").path
        let agent = SSHAgent(socketPath: socketPath)
        try agent.start()

        // Generate an ed25519 keypair using system ssh-keygen
        let keyPath = tmp.appendingPathComponent("user")
        let (rcGen, outGen) = runCommand("/usr/bin/ssh-keygen", args: ["-t", "ed25519", "-f", keyPath.path, "-N", ""])
        XCTAssertEqual(rcGen, 0, "ssh-keygen failed: \(outGen)")

        // Use ssh-add to add the private key to our in-process agent
        let env = ["SSH_AUTH_SOCK": socketPath]
        let (rcAdd, outAdd) = runCommandEnv("/usr/bin/ssh-add", args: [keyPath.path], env: env)
        XCTAssertEqual(rcAdd, 0, "ssh-add failed: \(outAdd)")

        // List identities via ssh-add -L and ensure our public key is present
        let (rcList, outList) = runCommandEnv("/usr/bin/ssh-add", args: ["-L"], env: env)
        XCTAssertEqual(rcList, 0, "ssh-add -L failed: \(outList)")

        let pubData = try Data(contentsOf: keyPath.appendingPathExtension("pub"))
        guard let pubStr = String(data: pubData, encoding: .utf8) else { XCTFail("cannot read pub"); return }
        let comps = pubStr.split(separator: " ")
        XCTAssertGreaterThanOrEqual(comps.count, 2)
        let b64 = String(comps[1])
        XCTAssertTrue(outList.contains(b64) || outList.contains("ssh-ed25519"), "ssh-add -L output did not include our key: \(outList)")
    }
}
