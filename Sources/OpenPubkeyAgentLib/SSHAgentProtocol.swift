// SSHAgentProtocol.swift
// Minimal SSH agent protocol constants and message parsing for Ed25519 keys
// macOS only

import Foundation

public enum SSHAgentMessageType: UInt8 {
    case requestIdentities = 11 // SSH2_AGENTC_REQUEST_IDENTITIES
    case identitiesAnswer = 12  // SSH2_AGENT_IDENTITIES_ANSWER
    case signRequest = 13       // SSH2_AGENTC_SIGN_REQUEST
    case signResponse = 14      // SSH2_AGENT_SIGN_RESPONSE
}

public struct SSHAgentIdentity {
    public let publicKey: Data
    public let comment: String
    public init(publicKey: Data, comment: String) {
        self.publicKey = publicKey
        self.comment = comment
    }
}

public struct SSHAgentMessage {
    public let type: SSHAgentMessageType
    public let payload: Data
}

extension Data {
    public func toUInt32(offset: Int) -> UInt32 {
        let b0 = UInt32(self[offset])
        let b1 = UInt32(self[offset+1])
        let b2 = UInt32(self[offset+2])
        let b3 = UInt32(self[offset+3])
        return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
    }
    public func toString(offset: Int, length: Int) -> String {
        let sub = self.subdata(in: offset..<(offset+length))
        return String(data: sub, encoding: .utf8) ?? ""
    }
}
