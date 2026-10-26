// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Pastoral",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(name: "Pastoral", targets: ["Pastoral"]),
        .executable(name: "pastoral-helper", targets: ["PastoralHelper"]),
        .library(name: "PastoralCore", targets: ["PastoralCore"]),
        .library(name: "PastoralProxy", targets: ["PastoralProxy"])
    ],
    targets: [
        // Main SwiftUI app — the GUI client. Runs unprivileged.
        .executableTarget(
            name: "Pastoral",
            dependencies: ["PastoralCore", "PastoralProxy"],
            path: "Sources/Pastoral",
            resources: [
                .copy("Resources")
            ]
        ),

        // libpcap source, packaged as a C target so we don't depend on the
        // system libpcap being present. Pre-configured for macOS (BPF) with
        // a generated config.h. Linked statically into the targets that
        // need packet capture.
        .target(
            name: "libpcap",
            path: "Sources/libpcap",
            publicHeadersPath: ".",
            cSettings: [
                .define("BUILDING_PCAP"),
                .define("pcap_EXPORTS"),
                .define("HAVE_CONFIG_H"),
                .headerSearchPath(".")
            ]
        ),

        // Shared, testable core: helper protocol models, command dispatch,
        // ARP frame assembly, Ethernet/IP/TCP decode, OUI lookup, leaf cert
        // issuance, intercept-decision logic. No UI, no I/O side effects
        // beyond what is injected — keeps it unit-testable.
        .target(
            name: "PastoralCore",
            dependencies: ["libpcap"],
            path: "Sources/PastoralCore"
        ),

        // BPF ioctl shim: exposes BIOCSETIF/BIOCGBLEN/BIOCIMMEDIATE and
        // bpf_hdr size to Swift. The _IOW/_IOR macros behind these aren't
        // available in the SPM C module compilation context, so we wrap
        // them in a small C target.
        .target(
            name: "PastoralBPFShim",
            path: "Sources/PastoralBPFShim",
            publicHeadersPath: "include"
        ),

        // Privileged helper daemon. Installed by the .pkg at
        // /usr/local/sbin/pastoral-helper and launched by launchd via socket
        // activation on /var/run/pastoral.sock. Speaks the line-delimited
        // JSON protocol defined in PastoralCore.
        .executableTarget(
            name: "PastoralHelper",
            dependencies: ["PastoralCore", "libpcap", "PastoralBPFShim"],
            path: "Sources/PastoralHelper"
        ),

        // Transparent MITM proxy. Listens on 127.0.0.1:8080, handles plain
        // HTTP (parse + forward + capture) and CONNECT for TLS (tunnel +
        // SNI capture). Written with Network.framework. Separate target so
        // it's testable in isolation.
        .target(
            name: "PastoralProxy",
            dependencies: ["PastoralCore"],
            path: "Sources/PastoralProxy"
        ),

        // Unit tests for PastoralCore.
        .testTarget(
            name: "PastoralTests",
            dependencies: ["PastoralCore"],
            path: "Tests/PastoralTests"
        ),
        .testTarget(
            name: "PastoralAppTests",
            dependencies: ["Pastoral"],
            path: "Tests/PastoralAppTests"
        ),

        // Integration tests for the proxy: start it, make a local request
        // through it, verify the captured log.
        .testTarget(
            name: "PastoralProxyTests",
            dependencies: ["PastoralProxy"],
            path: "Tests/PastoralProxyTests"
        )
    ]
)
