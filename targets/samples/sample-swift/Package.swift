// swift-tools-version:5.7
import PackageDescription

let package = Package(
    name: "sample-swift",
    targets: [
        .executableTarget(
            name: "sample-swift",
            path: "Sources/sample-swift"
        )
    ]
)
