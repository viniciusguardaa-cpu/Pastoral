import Testing
import SwiftUI
@testable import Pastoral

@Suite("Design preview")
@MainActor
struct DesignPreviewTests {
    @Test("Render native views without network operations",
          .enabled(if: ProcessInfo.processInfo.environment["PASTORAL_RENDER_DIR"] != nil))
    func render() throws {
        let directory = try #require(ProcessInfo.processInfo.environment["PASTORAL_RENDER_DIR"])
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        _ = NSApplication.shared
        let scenarios: [(String, CGFloat, CGFloat, PastoralTab, Bool)] = [
            ("pastoral-overview", 1260, 860, .overview, true),
            ("pastoral-compact", 1100, 760, .overview, true),
            ("pastoral-devices", 1260, 860, .kill, true),
            ("pastoral-offline", 1100, 760, .settings, false)
        ]
        for (name, width, height, tab, online) in scenarios {
            let state = AppState(restoreRequest: { _ in Issue.record("Preview attempted a helper request"); return .error(message: "disabled") })
            state.loadDesignPreview()
            state.selectedTab = tab
            if !online { state.helper = .offline }
            let content = ContentView(state: state, preview: true).frame(width: width, height: height)
            let view = NSHostingView(rootView: content)
            view.frame = NSRect(x: 0, y: 0, width: width, height: height)
            let window = NSWindow(contentRect: view.frame, styleMask: [.borderless], backing: .buffered, defer: false)
            window.contentView = view
            view.layoutSubtreeIfNeeded()
            let bitmap = try #require(view.bitmapImageRepForCachingDisplay(in: view.bounds))
            view.cacheDisplay(in: view.bounds, to: bitmap)
            let png = try #require(bitmap.representation(using: .png, properties: [:]))
            try png.write(to: URL(fileURLWithPath: directory).appendingPathComponent(name + ".png"))
            window.orderOut(nil)
        }
    }
}
