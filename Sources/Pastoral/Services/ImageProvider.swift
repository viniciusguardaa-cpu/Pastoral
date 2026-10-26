import Foundation
import AppKit
import ImageIO
import UniformTypeIdentifiers
import PastoralCore

// MARK: - Image loading + transcoding for injection
//
// Turns a user-picked file (or folder, for rotation) into PreparedImages:
// PNG/JPEG/GIF pass through with light normalization, SVG is served raw,
// and anything else ImageIO decodes becomes PNG. Resizing uses
// CoreGraphics — no external dependencies.

final class ImageProvider: @unchecked Sendable {
    /// Types the picker accepts.
    static let imageUTTypes: [UTType] = [
        .png, .jpeg, .gif, .webP, .heic, .tiff, .bmp, .svg
    ]
    /// Cap on rotation-pool size and source file size (guard rails for a
    /// folder of RAW files).
    static let maxImages = 64
    static let maxSourceBytes = 20 * 1024 * 1024

    /// Open-panel for a single image file.
    @MainActor func pickImage() -> URL? {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = Self.imageUTTypes
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        return panel.runModal() == .OK ? panel.url : nil
    }

    /// Open-panel for a folder of images (rotation pool).
    @MainActor func pickFolder() -> URL? {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        return panel.runModal() == .OK ? panel.url : nil
    }

    /// Load all servable images under a URL — the file itself, or the
    /// top-level contents of a folder (non-recursive, sorted for stable
    /// rotation order).
    func load(from url: URL) -> [PreparedImage] {
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir)
        else { return [] }

        let files: [URL]
        if isDir.boolValue {
            files = (try? FileManager.default.contentsOfDirectory(
                at: url, includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles]))?
                .sorted { $0.lastPathComponent < $1.lastPathComponent } ?? []
        } else {
            files = [url]
        }

        return files.prefix(Self.maxImages).compactMap { preparedImage(from: $0) }
    }

    /// Prepare a single file for injection.
    ///
    /// - SVG: served as raw bytes (ImageIO can't rasterize it, and raw SVG
    ///   also carries any embedded payload).
    /// - GIF: served raw so animation survives.
    /// - PNG/JPEG: re-encoded to the same format (strips oddities).
    /// - Everything else ImageIO decodes → PNG.
    func preparedImage(from url: URL) -> PreparedImage? {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
              let size = attrs[.size] as? Int, size <= Self.maxSourceBytes else {
            return nil
        }
        let ext = url.pathExtension.lowercased()

        if ext == "svg" {
            guard let data = try? Data(contentsOf: url) else { return nil }
            return PreparedImage(data: data, contentType: "image/svg+xml")
        }
        if ext == "gif" {
            guard let data = try? Data(contentsOf: url),
                  let src = CGImageSourceCreateWithData(data as CFData, nil),
                  let props = CGImageSourceCopyPropertiesAtIndex(src, 0, nil)
                      as? [String: Any] else { return nil }
            return PreparedImage(data: data, contentType: "image/gif",
                                 pixelWidth: props[kCGImagePropertyPixelWidth as String] as? Int,
                                 pixelHeight: props[kCGImagePropertyPixelHeight as String] as? Int)
        }

        guard let src = CGImageSourceCreateWithURL(url as CFURL, nil),
              let cg = CGImageSourceCreateImageAtIndex(src, 0, nil) else {
            return nil
        }

        let utType: UTType = ext == "jpg" || ext == "jpeg" ? .jpeg : .png
        guard let data = encode(cg, as: utType) else { return nil }
        return PreparedImage(data: data,
                             contentType: utType == .jpeg ? "image/jpeg" : "image/png",
                             pixelWidth: cg.width, pixelHeight: cg.height)
    }

    /// Resize a prepared image to exact dimensions (the `resizer` hook the
    /// InjectionEngine calls when `preserveDimensions` is on and the
    /// request URL carries a size hint). SVG/GIF return nil — the engine
    /// falls back to the unscaled bytes.
    func resized(_ img: PreparedImage, width: Int, height: Int) -> PreparedImage? {
        guard img.contentType != "image/svg+xml",
              img.contentType != "image/gif",
              width > 0, height > 0,
              let src = CGImageSourceCreateWithData(img.data as CFData, nil),
              let cg = CGImageSourceCreateImageAtIndex(src, 0, nil),
              let ctx = CGContext(data: nil, width: width, height: height,
                                  bitsPerComponent: 8, bytesPerRow: 0,
                                  space: CGColorSpaceCreateDeviceRGB(),
                                  bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)
        else { return nil }

        ctx.interpolationQuality = .high
        ctx.draw(cg, in: CGRect(x: 0, y: 0, width: width, height: height))
        guard let scaled = ctx.makeImage() else { return nil }

        let utType: UTType = img.contentType == "image/jpeg" ? .jpeg : .png
        guard let data = encode(scaled, as: utType) else { return nil }
        return PreparedImage(data: data, contentType: img.contentType,
                             pixelWidth: width, pixelHeight: height)
    }

    /// Encode a CGImage to PNG/JPEG via ImageIO.
    private func encode(_ image: CGImage, as type: UTType) -> Data? {
        let out = NSMutableData()
        guard let dest = CGImageDestinationCreateWithData(
            out as CFMutableData, type.identifier as CFString, 1, nil) else {
            return nil
        }
        CGImageDestinationAddImage(dest, image, nil)
        guard CGImageDestinationFinalize(dest) else { return nil }
        return out as Data
    }
}
