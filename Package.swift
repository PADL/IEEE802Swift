// swift-tools-version: 6.2

import PackageDescription

let CommonSwiftSettings: [SwiftSetting] = [
  .enableExperimentalFeature("StrictConcurrency"),
  .enableExperimentalFeature("NonisolatedNonsendingByDefault"),
]

var Products: [Product] = [
  .library(name: "IEEE802", targets: ["IEEE802"]),
]

var Dependencies: [Package.Dependency] = [
  .package(url: "https://github.com/apple/swift-system", from: "1.2.1"),
  .package(url: "https://github.com/apple/swift-binary-parsing", from: "0.0.2"),
]

var Targets: [Target] = [
  .target(
    name: "IEEE802",
    dependencies: [
      .product(name: "SystemPackage", package: "swift-system"),
      .product(name: "BinaryParsing", package: "swift-binary-parsing"),
    ],
    swiftSettings: CommonSwiftSettings
  ),
  .testTarget(
    name: "IEEE802Tests",
    dependencies: ["IEEE802"],
    swiftSettings: CommonSwiftSettings
  ),
]

// Raw AF_PACKET sockets driven by io_uring; Linux only.
#if os(Linux)
Products += [
  .library(name: "IEEE802Linux", targets: ["IEEE802Linux"]),
]

Dependencies += [
  .package(url: "https://github.com/PADL/IORingSwift", from: "2.0.0"),
  .package(url: "https://github.com/PADL/SocketAddress", from: "0.5.2"),
  .package(url: "https://github.com/lhoward/AsyncExtensions", from: "0.9.2"),
]

Targets += [
  .target(
    name: "IEEE802Linux",
    dependencies: [
      "IEEE802",
      .product(name: "IORing", package: "IORingSwift"),
      .product(name: "IORingUtils", package: "IORingSwift"),
      .product(name: "SocketAddress", package: "SocketAddress"),
      .product(name: "AsyncExtensions", package: "AsyncExtensions"),
      .product(name: "SystemPackage", package: "swift-system"),
    ],
    swiftSettings: CommonSwiftSettings
  ),
]
#endif

let package = Package(
  name: "IEEE802Swift",
  platforms: [
    .macOS(.v26),
  ],
  products: Products,
  dependencies: Dependencies,
  targets: Targets
)
