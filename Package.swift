// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "OpenPubkeyAgent",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "OpenPubkeyAgent", targets: ["OpenPubkeyAgentApp"]),
        .executable(name: "certgen", targets: ["certgen"]),
    ],
    targets: [
        .target(
            name: "OpenPubkeyAgent",
            path: "Sources/OpenPubkeyAgentLib"
        ),
        .executableTarget(
            name: "OpenPubkeyAgentApp",
            dependencies: ["OpenPubkeyAgent"],
            path: "Sources/App"
        ),
        .executableTarget(
            name: "certgen",
            dependencies: ["OpenPubkeyAgent"],
            path: "Tools/CertGen"
        ),
        .testTarget(
            name: "OpenPubkeyAgentTests",
            dependencies: ["OpenPubkeyAgent"],
            path: "Tests"
        )
    ]
)
