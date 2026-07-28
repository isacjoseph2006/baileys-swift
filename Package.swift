// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "BaileysSwift",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "BaileysSwift", targets: ["BaileysSwift"]),
        .executable(name: "baileys-cli", targets: ["BaileysSwiftCLI"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        .package(url: "https://github.com/vapor/websocket-kit.git", from: "2.16.2"),
        .package(url: "https://github.com/apple/swift-protobuf.git", from: "1.27.0"),
    ],
    targets: [
        .systemLibrary(name: "CZlib"),
        .target(
            name: "BaileysSwift",
            dependencies: [
                "CZlib",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "WebSocketKit", package: "websocket-kit"),
                .product(name: "SwiftProtobuf", package: "swift-protobuf"),
            ],
            exclude: [
                "Proto/WAProto.proto",
                "Proto/regenerate.sh",
                "Proto/fetch-and-patch.py",
            ]
        ),
        .executableTarget(
            name: "BaileysSwiftCLI",
            dependencies: ["BaileysSwift"]
        ),
        .testTarget(
            name: "BaileysSwiftTests",
            dependencies: ["BaileysSwift"]
        ),
    ]
)
