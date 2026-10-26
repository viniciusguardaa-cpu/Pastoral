// Generates Tests/fixtures/frame.jpg (small solid-color JPEG) for the RTSP
// integration tests. Run once:
//   swift Scripts/dev-make-test-jpeg.swift
import AppKit

let size = NSSize(width: 64, height: 48)
guard let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: 64, pixelsHigh: 48,
                                 bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
                                 isPlanar: false, colorSpaceName: .deviceRGB,
                                 bytesPerRow: 0, bitsPerPixel: 0) else {
    fatalError("bitmap")
}
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
NSColor(calibratedRed: 0.8, green: 0.1, blue: 0.1, alpha: 1).setFill()
NSRect(origin: .zero, size: size).fill()
NSColor(calibratedRed: 0.1, green: 0.1, blue: 0.8, alpha: 1).setFill()
NSRect(x: 8, y: 8, width: 16, height: 16).fill()
NSGraphicsContext.restoreGraphicsState()
guard let data = rep.representation(using: .jpeg, properties: [.compressionFactor: 0.8]) else {
    fatalError("jpeg")
}
let url = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent().deletingLastPathComponent()
    .appendingPathComponent("Tests/fixtures/frame.jpg")
try! data.write(to: url)
print("wrote \(url.path) (\(data.count) bytes)")
