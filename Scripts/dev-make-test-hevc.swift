// Encodes a few tiny HEVC frames with VideoToolbox (VTCompressionSession)
// and writes the resulting NAL units (hex, one per line) into
// Tests/fixtures/test.hevc.nals.txt for the RTSP integration tests.
// Run once:
//   swift Scripts/dev-make-test-hevc.swift
import CoreVideo
import CoreMedia
import VideoToolbox
import Foundation

func dbg(_ m: String) { FileHandle.standardError.write((m + "\n").data(using: .utf8)!) }

let w = 320, h = 240

final class NALCollector {
    let lock = NSLock()
    var nals: [[UInt8]] = []
    var paramSets: [[UInt8]] = []   // VPS/SPS/PPS, taken from the sample's format description
    func append(_ n: [UInt8]) { lock.lock(); nals.append(n); lock.unlock() }
    func setParams(_ p: [[UInt8]]) { lock.lock(); paramSets = p; lock.unlock() }
}
let collector = NALCollector()

func makeFrame(_ i: Int) -> CVPixelBuffer {
    var pb: CVPixelBuffer?
    assert(CVPixelBufferCreate(kCFAllocatorDefault, w, h,
                               kCVPixelFormatType_420YpCbCr8BiPlanarFullRange, nil, &pb) == kCVReturnSuccess)
    let buffer = pb!
    CVPixelBufferLockBaseAddress(buffer, [])
    let yRow = CVPixelBufferGetBytesPerRow(buffer)
    let y0 = CVPixelBufferGetBaseAddressOfPlane(buffer, 0)!.assumingMemoryBound(to: UInt8.self)
    let y1 = CVPixelBufferGetBaseAddressOfPlane(buffer, 1)!.assumingMemoryBound(to: UInt8.self)
    for yy in 0..<h { for xx in 0..<w { y0[yy * yRow + xx] = UInt8((xx / 4 + 32 * i) % 256) } }
    for yy in 0..<(h / 2) {
        for xx in 0..<(w / 2) {
            y1[yy * (yRow / 2) + 2 * xx] = UInt8(96 + 8 * i)
            y1[yy * (yRow / 2) + 2 * xx + 1] = UInt8(128 + 8 * i)
        }
    }
    CVPixelBufferUnlockBaseAddress(buffer, [])
    return buffer
}

var session: VTCompressionSession?
let st = VTCompressionSessionCreate(allocator: kCFAllocatorDefault,
                                    width: Int32(w), height: Int32(h),
                                    codecType: kCMVideoCodecType_HEVC,
                                    encoderSpecification: nil,
                                    imageBufferAttributes: [String(kCVPixelBufferPixelFormatTypeKey): kCVPixelFormatType_420YpCbCr8BiPlanarFullRange] as CFDictionary,
                                    compressedDataAllocator: kCFAllocatorDefault,
                                    outputCallback: { _, _, _, _, sb in
                                        guard let sb else { return }
                                        // The HEVC encoder keeps VPS/SPS/PPS out of the
                                        // compressed samples — they only live in the
                                        // format description. Grab them from the first
                                        // sample so the fixture carries them.
                                        if collector.paramSets.isEmpty,
                                           let fd = CMSampleBufferGetFormatDescription(sb) {
                                            collector.setParams(Array(fd.parameterSets).map(Array.init))
                                            dbg("paramsets: \(collector.paramSets.map { $0.count })")
                                        }
                                        guard let block = CMSampleBufferGetDataBuffer(sb) else { return }
                                        let total = CMBlockBufferGetDataLength(block)
                                        guard total >= 4 else { return }
                                        var data = [UInt8](repeating: 0, count: total)
                                        data.withUnsafeMutableBufferPointer { p in
                                            _ = CMBlockBufferCopyDataBytes(block, atOffset: 0, dataLength: total,
                                                                             destination: p.baseAddress!)
                                        }
                                        var pos = 0
                                        while pos + 4 <= total {
                                            let len = Int(data[pos]) << 24 | Int(data[pos + 1]) << 16 | Int(data[pos + 2]) << 8 | Int(data[pos + 3])
                                            pos += 4
                                            guard len > 0, pos + len <= total else { break }
                                            collector.append(Array(data[pos..<(pos + len)]))
                                            pos += len
                                        }
                                    }, refcon: nil,
                                    compressionSessionOut: &session)
dbg("create \(st)")
let prep = VTCompressionSessionPrepareToEncodeFrames(session!)
dbg("prepare \(prep)")
assert(prep == kCVReturnSuccess)

for i in 0..<10 {
    var infoFlags: VTEncodeInfoFlags = []
    // Frame 0 must be a key frame so the stream starts with an IDR.
    var props: [String: AnyObject]? = nil
    if i == 0 {
        props = ["ForceKeyFrame": kCFBooleanTrue!] as [String: AnyObject]
    }
    let e = VTCompressionSessionEncodeFrame(session!, imageBuffer: makeFrame(i),
                                            presentationTimeStamp: CMTime(value: CMTimeValue(i), timescale: 25),
                                            duration: CMTime(value: 1, timescale: 25),
                                            frameProperties: props.map { $0 as CFDictionary }, sourceFrameRefcon: nil,
                                            infoFlagsOut: &infoFlags)
    dbg("enc \(i) -> \(e) flags=\(infoFlags)")
}
let c = VTCompressionSessionCompleteFrames(session!, untilPresentationTimeStamp: CMTime(value: 2_147_483_647, timescale: 2_147_483_647))
dbg("complete \(c)")
assert(c == kCVReturnSuccess)

let allNals = collector.paramSets + collector.nals
let types = allNals.map { $0.first.map { ($0 >> 3) & 0x3F } ?? 99 }
dbg("nals=\(allNals.count) (params=\(collector.paramSets.count)) types=\(types)")
guard !allNals.isEmpty else { dbg("no NALs"); exit(1) }

let outURL = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent().deletingLastPathComponent()
    .appendingPathComponent("Tests/fixtures/test.hevc.nals.txt")
try! allNals.map { $0.map { String(format: "%02x", $0) }.joined() }
    .joined(separator: "\n").write(to: outURL, atomically: true, encoding: .utf8)
print("wrote \(outURL.path) (\(allNals.count) NALs)")
