import Foundation
import CoreMedia
import CoreVideo
import VideoToolbox
import CoreGraphics
import AppKit

// MARK: - H.264/HEVC decoder (VideoToolbox wrapper)
//
// Takes raw NAL units (as received from RTP de-encapsulation) and
// initializes a VTDecompressionSession once the parameter sets are seen.
// Supports H.264 (SPS=7/PPS=8 → CreateFromH264ParameterSets) and
// H.265/HEVC (VPS=32/SPS=33/PPS=34 → CreateFromHEVCParameterSets); the
// codec kind is auto-detected from the first parameter set. Both codecs
// feed length-prefixed (AVCC-style, 4-byte) samples.
//
// NOTE: The VideoToolbox callback API requires @convention(c) functions
// which can't capture state. We use an Unmanaged refcon to pass `self`
// back through the callback. Thread-safe via a serial dispatch queue.

final class H264Decoder: @unchecked Sendable {
    private enum Kind { case h264, hevc }
    private var formatDescription: CMVideoFormatDescription?
    private var decompressionSession: VTDecompressionSession?
    private let queue = DispatchQueue(label: "pastoral.h264.decoder")
    private let lock = NSLock()
    private var kind: Kind?
    private var vps: [UInt8]?   // HEVC only
    private var sps: [UInt8]?
    private var pps: [UInt8]?
    private var ciContext: CIContext?   // built once, reused per frame
    private var sampleCounter = 0      // sequential PTS for decoded samples

    /// Callback for decoded frames. Called on the VideoToolbox callback
    /// thread — callers should hop to the main thread for UI updates.
    var onFrame: ((CGImage) -> Void)?

    /// Feed a raw NAL unit (with the 1-byte header, no start code).
    /// Parameter sets (SPS/PPS/VPS) are buffered; once all are present
    /// the VideoToolbox session is created. VCL NAL units are decoded and
    /// emitted as CGImages via the callback.
    func feed(nalUnit: [UInt8]) {
        guard !nalUnit.isEmpty else { return }
        let first = nalUnit[0]

        // NAL type extraction differs per codec: H.264 keeps the 5-bit type in
        // the low bits; HEVC's header is F(1)|Type(6)|LayerId(6)|TID(3)
        // (RFC 7798 §1.1.4), so Type sits at bits [6:1] — same shift FFmpeg's
        // hevc_parse_nal_header uses ((b0 >> 1) & 0x3F with F = 0).
        switch kind {
        case .h264:
            feedH264(nalUnit: nalUnit, type: Int(first) & 0x1F)
        case .hevc:
            feedHEVC(nalUnit: nalUnit, type: (Int(first) >> 1) & 0x3F)
        case nil:
            // First NAL decides the codec from its parameter-set shape.
            let tHevc = (Int(first) >> 1) & 0x3F
            let t264 = Int(first) & 0x1F
            if (32...34).contains(tHevc) {
                kind = .hevc
                feed(nalUnit: nalUnit)
            } else if t264 == 7 || t264 == 8 {
                kind = .h264
                feed(nalUnit: nalUnit)
            }
            // Unrecognized header before classification — nothing safe to do.
        }
    }

    private func feedH264(nalUnit: [UInt8], type: Int) {
        switch type {
        case 7:   // SPS
            sps = nalUnit
            tryCreateSession()
        case 8:   // PPS
            pps = nalUnit
            tryCreateSession()
        case 1...5:
            // VCL slice (H.264 types 2-4 rarely used) — decode() no-ops until
            // the session exists.
            decode(nalUnit: nalUnit)
        default:
            break   // SEI/AUD/etc. — ignored
        }
    }

    private func feedHEVC(nalUnit: [UInt8], type: Int) {
        switch type {
        case 32:  // VPS
            vps = nalUnit
            tryCreateSession()
        case 33:  // SPS
            sps = nalUnit
            tryCreateSession()
        case 34:  // PPS
            pps = nalUnit
            tryCreateSession()
        case 0...31:
            // VCL slice (TRAIL/TSA/IDR/CRA/…). STAP-A (24) and FU-A (28) are
            // reassembled by the RTP layer before reaching here.
            decode(nalUnit: nalUnit)
        default:
            break   // 35+ (AUD, SEI…) — ignored
        }
    }

    // MARK: - Session creation

    private func tryCreateSession() {
        lock.lock()
        guard sps != nil, pps != nil, decompressionSession == nil, kind != nil else {
            lock.unlock(); return
        }
        let kindNow = kind!
        let spsNow = sps!
        let ppsNow = pps!
        let vpsNow = vps
        lock.unlock()

        queue.sync {
            guard decompressionSession == nil else { return }

            // Build the CMVideoFormatDescription from the parameter sets,
            // passed as raw NAL units (starting with the NAL header byte).
            var desc: CMVideoFormatDescription?
            let status: OSStatus
            let setSizes: [Int]
            switch kindNow {
            case .h264:
                setSizes = [spsNow.count, ppsNow.count]
                status = CMVideoFormatDescriptionCreateFromH264ParameterSets(
                    allocator: kCFAllocatorDefault,
                    parameterSetCount: 2,
                    parameterSetPointers: makePointers([spsNow, ppsNow]),
                    parameterSetSizes: [spsNow.count, ppsNow.count],
                    nalUnitHeaderLength: 4,
                    formatDescriptionOut: &desc)
            case .hevc:
                let sets = [vpsNow, spsNow, ppsNow].compactMap { $0 }
                setSizes = sets.map { $0.count }
                status = CMVideoFormatDescriptionCreateFromHEVCParameterSets(
                    allocator: kCFAllocatorDefault,
                    parameterSetCount: sets.count,
                    parameterSetPointers: makePointers(sets),
                    parameterSetSizes: sets.map { $0.count },
                    nalUnitHeaderLength: 4,
                    extensions: nil,   // no H.265 extensions carried
                    formatDescriptionOut: &desc)
            }
            guard status == noErr, let desc else {
                // TEMP DEBUG
                if ProcessInfo.processInfo.environment["PASTORAL_RTSP_DEBUG"] != nil {
                    print("vtb: CreateFrom…ParameterSets(\(kindNow)) falhou, status=\(status) sets=\(setSizes)")
                }
                return
            }
            self.formatDescription = desc

            // Create the decompression session with a C callback.
            let refcon = Unmanaged.passUnretained(self).toOpaque()
            var callbackRecord = VTDecompressionOutputCallbackRecord(
                decompressionOutputCallback: h264DecodeCallback,
                decompressionOutputRefCon: refcon)

            var session: VTDecompressionSession?
            let sessionStatus = VTDecompressionSessionCreate(
                allocator: kCFAllocatorDefault,
                formatDescription: desc,
                decoderSpecification: nil,
                imageBufferAttributes: nil,
                outputCallback: &callbackRecord,
                decompressionSessionOut: &session)
            if sessionStatus == noErr {
                self.decompressionSession = session
                // TEMP DEBUG
                if ProcessInfo.processInfo.environment["PASTORAL_RTSP_DEBUG"] != nil {
                    print("vtb: sessão criada (\(kindNow))")
                }
            } else {
                // TEMP DEBUG
                if ProcessInfo.processInfo.environment["PASTORAL_RTSP_DEBUG"] != nil {
                    print("vtb: VTDecompressionSessionCreate falhou, status=\(sessionStatus)")
                }
            }
        }
    }

    /// Keeps the NAL arrays alive (copied into `formatDescriptionStorage`,
    /// which outlives the one-shot C call) and returns pointers into them.
    private var formatDescriptionStorage: [[UInt8]] = []

    private func makePointers(_ sets: [[UInt8]]) -> UnsafePointer<UnsafePointer<UInt8>> {
        lock.lock()
        formatDescriptionStorage = sets
        lock.unlock()
        let ptrs = UnsafeMutablePointer<UnsafePointer<UInt8>>.allocate(capacity: max(1, sets.count))
        for (i, set) in sets.enumerated() {
            set.withUnsafeBufferPointer { buf in ptrs[i] = buf.baseAddress! }
        }
        // The pointer array is intentionally not deallocated: it must stay
        // valid across the C call and is tiny (one-shot per session).
        return UnsafePointer(ptrs)
    }

    // MARK: - Decode

    private func decode(nalUnit: [UInt8]) {
        queue.async { [weak self] in
            guard let self, let session = self.decompressionSession,
                  let desc = self.formatDescription else { return }

            // Convert to AVCC (length-prefixed) for VideoToolbox.
            var avccNAL = [UInt8](repeating: 0, count: 4)
            let len = UInt32(nalUnit.count).bigEndian
            withUnsafeBytes(of: len) { ptr in
                avccNAL[0] = ptr[0]; avccNAL[1] = ptr[1]
                avccNAL[2] = ptr[2]; avccNAL[3] = ptr[3]
            }
            avccNAL.append(contentsOf: nalUnit)

            // Create a CMBlockBuffer from the AVCC NAL.
            var blockBuffer: CMBlockBuffer?
            let totalLength = Int(avccNAL.count)
            CMBlockBufferCreateWithMemoryBlock(
                allocator: kCFAllocatorDefault,
                memoryBlock: nil,
                blockLength: totalLength,
                blockAllocator: kCFAllocatorDefault,
                customBlockSource: nil,
                offsetToData: 0,
                dataLength: totalLength,
                flags: 0,
                blockBufferOut: &blockBuffer
            )
            guard let bb = blockBuffer else { return }
            avccNAL.withUnsafeBytes { rawBuf in
                CMBlockBufferReplaceDataBytes(
                    with: rawBuf.baseAddress!,
                    blockBuffer: bb,
                    offsetIntoDestination: 0,
                    dataLength: Int(totalLength)
                )
            }

            // Create a CMSampleBuffer. A real presentation timestamp keeps
            // hardware HEVC decoders honest — all-invalid timing gets
            // dropped silently by some VT pipelines.
            let now = sampleCounter
            sampleCounter += 1
            let pts = CMTimeMake(value: Int64(now), timescale: 30)
            var sampleBuffer: CMSampleBuffer?
            var timing = CMSampleTimingInfo(
                duration: .invalid,
                presentationTimeStamp: pts,
                decodeTimeStamp: .invalid
            )
            var sampleSize = [Int](repeating: totalLength, count: 1)
            CMSampleBufferCreate(
                allocator: kCFAllocatorDefault,
                dataBuffer: bb,
                dataReady: true,
                makeDataReadyCallback: nil,
                refcon: nil,
                formatDescription: desc,
                sampleCount: 1,
                sampleTimingEntryCount: 1,
                sampleTimingArray: &timing,
                sampleSizeEntryCount: 1,
                sampleSizeArray: &sampleSize,
                sampleBufferOut: &sampleBuffer
            )
            guard let sb = sampleBuffer else { return }

            var flags: VTDecodeInfoFlags = []
            let decodeStatus = VTDecompressionSessionDecodeFrame(
                session,
                sampleBuffer: sb,
                flags: [],
                frameRefcon: nil,
                infoFlagsOut: &flags
            )
            // TEMP DEBUG
            if decodeStatus != noErr, ProcessInfo.processInfo.environment["PASTORAL_RTSP_DEBUG"] != nil {
                print("vtb: DecodeFrame falhou, status=\(decodeStatus) nal=\(nalUnit.count)B")
            }
        }
    }

    // MARK: - C callback (top-level, @convention(c))

    /// Static C callback for VideoToolbox. Casts the refcon back to
    /// H264Decoder and forwards the decoded frame.
    private let h264DecodeCallback: VTDecompressionOutputCallback = { _, refcon, status, _, imageBuffer, _, _ in
        // TEMP DEBUG
        if status != noErr, ProcessInfo.processInfo.environment["PASTORAL_RTSP_DEBUG"] != nil {
            print("vtb: callback de erro status=\(status)")
        }
        guard status == noErr, let imageBuffer else { return }
        // TEMP DEBUG
        if ProcessInfo.processInfo.environment["PASTORAL_RTSP_DEBUG"] != nil {
            print("vtb: frame decodificada \(CVPixelBufferGetWidth(imageBuffer))x\(CVPixelBufferGetHeight(imageBuffer))")
        }
        guard let refcon else {
            if ProcessInfo.processInfo.environment["PASTORAL_RTSP_DEBUG"] != nil { print("vtb: STAGE refcon nil") }
            return
        }
        // TEMP DEBUG
        if ProcessInfo.processInfo.environment["PASTORAL_RTSP_DEBUG"] != nil {
            print("vtb: STAGE refcon ok")
        }
        let decoder = Unmanaged<H264Decoder>.fromOpaque(refcon).takeUnretainedValue()
        // Reuse one CIContext instead of building a new one per frame
        // (context creation is expensive).
        decoder.lock.lock()
        if decoder.ciContext == nil { decoder.ciContext = CIContext() }
        let ciContext = decoder.ciContext!
        decoder.lock.unlock()
        // TEMP DEBUG
        if ProcessInfo.processInfo.environment["PASTORAL_RTSP_DEBUG"] != nil {
            print("vtb: STAGE ciContext pronto")
        }
        let ciImage = CIImage(cvPixelBuffer: imageBuffer)
        if let cgImage = ciContext.createCGImage(ciImage, from: ciImage.extent) {
            // TEMP DEBUG
            if ProcessInfo.processInfo.environment["PASTORAL_RTSP_DEBUG"] != nil {
                print("vtb: createCGImage ok, chamando onFrame (setada=\(decoder.onFrame != nil))")
            }
            decoder.onFrame?(cgImage)
        } else {
            // TEMP DEBUG
            if ProcessInfo.processInfo.environment["PASTORAL_RTSP_DEBUG"] != nil {
                print("vtb: createCGImage retornou nil")
            }
        }
    }
}
