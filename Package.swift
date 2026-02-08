// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "swift-quic",

    products: [
        // Main public API
        .library(
            name: "QUIC",
            targets: ["QUIC"]
        ),
        // Core types (no I/O dependencies)
        .library(
            name: "QUICCore",
            targets: ["QUICCore"]
        ),
        // QPACK header compression (RFC 9204)
        .library(
            name: "QPACK",
            targets: ["QPACK"]
        ),
        // HTTP/3 protocol (RFC 9114)
        .library(
            name: "HTTP3",
            targets: ["HTTP3"]
        ),
    ],
    dependencies: [
        // UDP transport
        .package(url: "https://github.com/hironichu/swift-nio-udp", branch: "main"),

        // Cryptography
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.2.0"),

        // X.509 Certificates and ASN.1
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.17.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.5.0"),

        // Logging
        .package(url: "https://github.com/apple/swift-log.git", from: "1.9.0"),

        // Documentation
        .package(url: "https://github.com/swiftlang/swift-docc-plugin.git", from: "1.4.3"),
    ],
    targets: [
        // MARK: - Core Types (No I/O)

        .target(
            name: "QUICCore",
            dependencies: [],
            path: "Sources/QUICCore"
        ),

        // MARK: - Crypto Layer

        .target(
            name: "QUICCrypto",
            dependencies: [
                "QUICCore",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ],
            path: "Sources/QUICCrypto",
            exclude: ["CONTEXT.md", "TLS/CONTEXT.md"]
        ),

        // MARK: - Connection Management

        .target(
            name: "QUICConnection",
            dependencies: [
                "QUICCore",
                "QUICCrypto",
                "QUICStream",
                "QUICRecovery",
            ],
            path: "Sources/QUICConnection",
            exclude: ["CONTEXT.md"]
        ),

        // MARK: - Stream Management

        .target(
            name: "QUICStream",
            dependencies: [
                "QUICCore",
            ],
            path: "Sources/QUICStream",
            exclude: ["CONTEXT.md"]
        ),

        // MARK: - Loss Detection & Congestion Control

        .target(
            name: "QUICRecovery",
            dependencies: [
                "QUICCore",
            ],
            path: "Sources/QUICRecovery",
            exclude: ["CONTEXT.md"]
        ),

        // MARK: - UDP Transport Integration

        .target(
            name: "QUICTransport",
            dependencies: [
                "QUICCore",
                .product(name: "NIOUDPTransport", package: "swift-nio-udp"),
            ],
            path: "Sources/QUICTransport"
        ),

        // MARK: - Main Public API

        .target(
            name: "QUIC",
            dependencies: [
                "QUICCore",
                "QUICCrypto",
                "QUICConnection",
                "QUICStream",
                "QUICRecovery",
                "QUICTransport",
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Sources/QUIC",
            exclude: ["CONTEXT.md"]
        ),

        // MARK: - QPACK (Header Compression, RFC 9204)

        .target(
            name: "QPACK",
            dependencies: [],
            path: "Sources/QPACK"
        ),

        // MARK: - HTTP/3 (RFC 9114)

        .target(
            name: "HTTP3",
            dependencies: [
                "QUIC",
                "QPACK",
                "QUICCore",
                "QUICStream",
            ],
            path: "Sources/HTTP3"
        ),

        // MARK: - Tests

        .testTarget(
            name: "QUICCoreTests",
            dependencies: ["QUICCore"],
            path: "Tests/QUICCoreTests"
        ),

        .testTarget(
            name: "QUICCryptoTests",
            dependencies: ["QUICCrypto"],
            path: "Tests/QUICCryptoTests"
        ),

        .testTarget(
            name: "QUICRecoveryTests",
            dependencies: ["QUICRecovery", "QUICCore"],
            path: "Tests/QUICRecoveryTests"
        ),

        .testTarget(
            name: "QUICStreamTests",
            dependencies: ["QUICStream", "QUICCore"],
            path: "Tests/QUICStreamTests"
        ),

        .testTarget(
            name: "QUICTests",
            dependencies: ["QUIC", "QUICRecovery", "QUICTransport"],
            path: "Tests/QUICTests"
        ),

        .testTarget(
            name: "QPACKTests",
            dependencies: ["QPACK"],
            path: "Tests/QPACKTests"
        ),

        .testTarget(
            name: "HTTP3Tests",
            dependencies: ["HTTP3", "QUIC", "QPACK", "QUICCore"],
            path: "Tests/HTTP3Tests"
        ),

        // MARK: - Benchmarks (run separately with: swift test --filter QUICBenchmarks)

        .testTarget(
            name: "QUICBenchmarks",
            dependencies: [
                "QUIC",
                "QUICCore",
                "QUICCrypto",
            ],
            path: "Tests/QUICBenchmarks"
        ),
    ]
)
