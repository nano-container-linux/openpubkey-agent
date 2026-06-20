#!/usr/bin/env swift
import Foundation

func readUInt32(_ data: Data, _ at: inout Int) -> UInt32 {
    let b0 = UInt32(data[at])
    let b1 = UInt32(data[at+1])
    let b2 = UInt32(data[at+2])
    let b3 = UInt32(data[at+3])
    at += 4
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
}

func safeReadUInt32(_ data: Data, _ at: inout Int) -> UInt32? {
    guard at + 4 <= data.count else { return nil }
    return readUInt32(data, &at)
}

func parse(_ path: String) {
    let url = URL(fileURLWithPath: path)
    guard let data = try? Data(contentsOf: url) else { print("ERR: cannot read \(path)"); return }
    print("\n== Parsing \(path) size=\(data.count)")
    var idx = 0
    guard idx + 4 <= data.count else { print("truncated header"); return }
    let certTypeLen = Int(readUInt32(data, &idx))
    print("cert-type len=\(certTypeLen) at 0x\(String(format: "%x", idx-4))")
    guard idx + certTypeLen <= data.count else { print("truncated cert-type"); return }
    let certType = String(data: data[idx..<(idx+certTypeLen)], encoding: .utf8) ?? "<bad>"
    print("cert-type=\(certType)")
    idx += certTypeLen
    guard let contentLenU = safeReadUInt32(data, &idx) else { print("no content len"); return }
    let contentLen = Int(contentLenU)
    print("content len=\(contentLen) at 0x\(String(format: "%x", idx-4))")
    let contentStart = idx
    guard contentStart + contentLen <= data.count else { print("content truncated"); return }
    var cidx = 0
    let content = data[contentStart..<(contentStart+contentLen)]
    // nonce
    guard let nonceLenU = safeReadUInt32(content, &cidx) else { print("no nonce len"); return }
    let nonceLen = Int(nonceLenU)
    print("nonce len=\(nonceLen) at 0x\(String(format: "%x", contentStart + cidx - 4))")
    guard cidx + nonceLen <= content.count else { print("truncated nonce"); return }
    print("nonce bytes: \(content[cidx..<(cidx+min(nonceLen,16))].map { String(format: "%02x", $0) }.joined())")
    cidx += nonceLen
    // pubkey field
    guard let pubFieldLenU = safeReadUInt32(content, &cidx) else { print("no pub field len"); return }
    let pubFieldLen = Int(pubFieldLenU)
    print("pubField len=\(pubFieldLen) at 0x\(String(format: "%x", contentStart + cidx - 4))")
    let pfStart = cidx
    guard let innerKeyTypeLenU = safeReadUInt32(content, &cidx) else { print("no inner key type len"); return }
    let innerKeyTypeLen = Int(innerKeyTypeLenU)
    print("inner key type len=\(innerKeyTypeLen) at 0x\(String(format: "%x", contentStart + cidx - 4))")
    guard cidx + innerKeyTypeLen <= content.count else { print("truncated inner key type"); return }
    let innerKeyType = String(data: content[cidx..<(cidx+innerKeyTypeLen)], encoding: .utf8) ?? "<bad>"
    print("inner key type=\(innerKeyType)")
    cidx += innerKeyTypeLen
    guard let innerKeyDataLenU = safeReadUInt32(content, &cidx) else { print("no inner key data len"); return }
    let innerKeyDataLen = Int(innerKeyDataLenU)
    print("inner key data len=\(innerKeyDataLen) at 0x\(String(format: "%x", contentStart + cidx - 4))")
    guard cidx + innerKeyDataLen <= content.count else { print("truncated inner key data"); return }
    print("inner key data hex: \(content[cidx..<(cidx+min(innerKeyDataLen,16))].map { String(format: "%02x", $0) }.joined())")
    cidx += innerKeyDataLen
    print("pubField consumed=\(cidx - pfStart) expected=\(pubFieldLen)")
    // serial
    guard cidx + 8 <= content.count else { print("truncated serial"); return }
    print("serial at 0x\(String(format: "%x", contentStart + cidx)) = \(content[cidx..<(cidx+8)].map { String(format: "%02x", $0) }.joined())")
    cidx += 8
    // cert type
    guard cidx + 4 <= content.count else { print("truncated certType"); return }
    print("certType at 0x\(String(format: "%x", contentStart + cidx)) = \(content[cidx..<(cidx+4)].map { String(format: "%02x", $0) }.joined())")
    cidx += 4
    // key id
    guard let kidLenU = safeReadUInt32(content, &cidx) else { print("no kid len"); return }
    let kidLen = Int(kidLenU)
    print("keyId len=\(kidLen) at 0x\(String(format: "%x", contentStart + cidx - 4))")
    guard cidx + kidLen <= content.count else { print("truncated keyId"); return }
    print("keyId=\(String(data: content[cidx..<(cidx+kidLen)], encoding: .utf8) ?? "<bad>")")
    cidx += kidLen
    // principals
    guard let prinsLenU = safeReadUInt32(content, &cidx) else { print("no prins len"); return }
    let prinsLen = Int(prinsLenU)
    print("principals len=\(prinsLen)")
    guard cidx + prinsLen <= content.count else { print("truncated principals"); return }
    cidx += prinsLen
    // validAfter/Before
    guard cidx + 16 <= content.count else { print("truncated validAfter/Before"); return }
    print("validAfter at 0x\(String(format: "%x", contentStart + cidx)) = \(content[cidx..<(cidx+8)].map { String(format: "%02x", $0) }.joined())")
    cidx += 8
    print("validBefore at 0x\(String(format: "%x", contentStart + cidx)) = \(content[cidx..<(cidx+8)].map { String(format: "%02x", $0) }.joined())")
    cidx += 8
    // critical options
    guard let critLenU = safeReadUInt32(content, &cidx) else { print("no crit len"); return }
    let critLen = Int(critLenU)
    print("crit len=\(critLen)")
    guard cidx + critLen <= content.count else { print("truncated critical options"); return }
    cidx += critLen
    // extensions
    guard let extLenU = safeReadUInt32(content, &cidx) else { print("no ext len"); return }
    let extLen = Int(extLenU)
    print("ext len=\(extLen)")
    guard cidx + extLen <= content.count else { print("truncated extensions"); return }
    cidx += extLen
    // reserved
    guard cidx + 4 <= content.count else { print("truncated reserved"); return }
    print("reserved at 0x\(String(format: "%x", contentStart + cidx)) = \(content[cidx..<(cidx+4)].map { String(format: "%02x", $0) }.joined())")
    cidx += 4
    // signature key
    guard let sigKeyLenU = safeReadUInt32(content, &cidx) else { print("no sigKey len"); return }
    let sigKeyLen = Int(sigKeyLenU)
    print("sigKey len=\(sigKeyLen) at 0x\(String(format: "%x", contentStart + cidx - 4))")
    let skStart = cidx
    guard let skTypeLenU = safeReadUInt32(content, &cidx) else { print("no sk type len"); return }
    let skTypeLen = Int(skTypeLenU)
    print("sigKey inner type len=\(skTypeLen)")
    guard cidx + skTypeLen <= content.count else { print("truncated sigKey inner type"); return }
    print("sigKey inner type=\(String(data: content[cidx..<(cidx+skTypeLen)], encoding: .utf8) ?? "<bad>")")
    cidx += skTypeLen
    guard let skDataLenU = safeReadUInt32(content, &cidx) else { print("no sk data len"); return }
    let skDataLen = Int(skDataLenU)
    print("sigKey inner data len=\(skDataLen) at 0x\(String(format: "%x", contentStart + cidx - 4))")
    guard cidx + skDataLen <= content.count else { print("truncated sigKey inner data"); return }
    print("sigKey inner data hex: \(content[cidx..<(cidx+min(skDataLen,32))].map { String(format: "%02x", $0) }.joined())")
    cidx += skDataLen
    print("sigKey consumed=\(cidx - skStart) expected=\(sigKeyLen)")
    // signature
    guard let sigLenU = safeReadUInt32(content, &cidx) else { print("no sig len"); return }
    let sigLen = Int(sigLenU)
    print("sig len=\(sigLen) at 0x\(String(format: "%x", contentStart + cidx - 4))")
    let sStart = cidx
    guard let sigAlgLenU = safeReadUInt32(content, &cidx) else { print("no sig alg len"); return }
    let sigAlgLen = Int(sigAlgLenU)
    print("sig alg len=\(sigAlgLen) at 0x\(String(format: "%x", contentStart + cidx - 4))")
    guard cidx + sigAlgLen <= content.count else { print("truncated sig alg"); return }
    print("sig alg=\(String(data: content[cidx..<(cidx+sigAlgLen)], encoding: .utf8) ?? "<bad>")")
    cidx += sigAlgLen
    guard let sigBlobLenU = safeReadUInt32(content, &cidx) else { print("no sig blob len"); return }
    let sigBlobLen = Int(sigBlobLenU)
    print("sig blob len=\(sigBlobLen) at 0x\(String(format: "%x", contentStart + cidx - 4))")
    guard cidx + sigBlobLen <= content.count else { print("truncated sig blob"); return }
    print("sig blob hex prefix: \(content[cidx..<(cidx+min(sigBlobLen,16))].map { String(format: "%02x", $0) }.joined())")
    cidx += sigBlobLen
    print("final remaining=\(content.count - cidx)")
}

let args = CommandLine.arguments
if args.count < 2 {
    print("Usage: parse_cert.swift <certfile> [<certfile2> ...]")
    exit(1)
}
for i in 1..<args.count { parse(args[i]) }
