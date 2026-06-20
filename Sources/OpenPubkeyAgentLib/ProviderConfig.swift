// ProviderConfig.swift
// Model for storing OIDC provider/key configuration
// All code comments and UI in English

import Foundation

public struct ProviderConfig: Codable, Equatable {
    public var provider: String
    public var clientId: String
    public var clientSecret: String
    public var oidcUrl: String
    public init(provider: String, clientId: String, clientSecret: String, oidcUrl: String) {
        self.provider = provider
        self.clientId = clientId
        self.clientSecret = clientSecret
        self.oidcUrl = oidcUrl
    }
}
