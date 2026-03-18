// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "OpenPubkeyAgent",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "OpenPubkeyAgent", targets: ["OpenPubkeyAgent"])
    ],
    targets: [
        .executableTarget(
            name: "OpenPubkeyAgent",
            path: "Sources"
        )
    ]
)
