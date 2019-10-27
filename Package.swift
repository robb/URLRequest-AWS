// swift-tools-version:5.1

import PackageDescription

let package = Package(
    name: "URLRequest+AWS",
    products: [
        .library(
            name: "URLRequest+AWS",
            targets: ["URLRequest+AWS"]),
    ],
    targets: [
        .target(
            name: "URLRequest+AWS",
            dependencies: []),
        .testTarget(
            name: "URLRequest+AWSTests",
            dependencies: ["URLRequest+AWS"]),
    ]
)
