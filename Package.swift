// swift-tools-version: 6.2

import PackageDescription

let CommonSwiftSettings: [SwiftSetting] = [
  .enableExperimentalFeature("StrictConcurrency"),
  .enableExperimentalFeature("NonisolatedNonsendingByDefault"),
]

// IEEE802Linux (raw AF_PACKET sockets driven by io_uring) only builds on Linux, but its product and
// target are declared on every host: a manifest is evaluated on the host, so a dependent whose
// manifest is evaluated on macOS (including one cross-compiling to Linux with a Swift SDK) must
// still find them. Its sources are wrapped in #if os(Linux) and its Linux-only dependencies are
// conditional, so on other platforms it builds an empty module.
let LinuxOnly: TargetDependencyCondition? = .when(platforms: [.linux])

let package = Package(
  name: "IEEE802Swift",
  platforms: [
    .macOS(.v26),
  ],
  products: [
    .library(name: "IEEE802", targets: ["IEEE802"]),
    .library(name: "IEEE802Linux", targets: ["IEEE802Linux"]),
  ],
  dependencies: [
    .package(url: "https://github.com/apple/swift-system", from: "1.2.1"),
    // pre-1.0, so a new minor version may break the API
    .package(url: "https://github.com/apple/swift-binary-parsing", .upToNextMinor(from: "0.0.2")),
    .package(url: "https://github.com/PADL/IORingSwift", from: "2.0.0"),
    .package(url: "https://github.com/PADL/SocketAddress", from: "0.5.2"),
    .package(url: "https://github.com/lhoward/AsyncExtensions", from: "0.9.2"),
  ],
  targets: [
    .target(
      name: "IEEE802",
      dependencies: [
        .product(name: "SystemPackage", package: "swift-system"),
        .product(name: "BinaryParsing", package: "swift-binary-parsing"),
      ],
      swiftSettings: CommonSwiftSettings
    ),
    .target(
      name: "IEEE802Linux",
      dependencies: [
        "IEEE802",
        .product(name: "IORing", package: "IORingSwift", condition: LinuxOnly),
        .product(name: "IORingUtils", package: "IORingSwift", condition: LinuxOnly),
        .product(name: "SocketAddress", package: "SocketAddress", condition: LinuxOnly),
        .product(name: "CLinuxSockAddr", package: "SocketAddress", condition: LinuxOnly),
        .product(name: "AsyncExtensions", package: "AsyncExtensions", condition: LinuxOnly),
        .product(name: "SystemPackage", package: "swift-system", condition: LinuxOnly),
      ],
      swiftSettings: CommonSwiftSettings
    ),
    .testTarget(
      name: "IEEE802Tests",
      dependencies: ["IEEE802"],
      swiftSettings: CommonSwiftSettings
    ),
  ]
)
