import Foundation
import SwiftUI

// MARK: - Camera info model
//
// A detected IP camera on the LAN. Derived from the Host list by the
// CameraDetector (Bonjour + OUI) and the port probe (RTSP/ONVIF/HTTP).
// Snapshots are stored separately in AppState.cameraSnapshots keyed by id.

/// How a camera was detected — drives the badge color in the UI.
enum CameraDetectionSource: String, Hashable, Sendable {
    case onvif        // answered WS-Discovery probe (UDP 3702)
    case bonjour      // _rtsp/_onvif/_camera/_h264/_h265 mDNS service
    case oui          // vendor MAC prefix (Hikvision, Dahua, Axis, …)
    case portProbe    // TCP probe found RTSP(554)/ONVIF(3702/8000)/HTTP(80)

    var label: String {
        switch self {
        case .onvif: return "ONVIF"
        case .bonjour: return "Bonjour"
        case .oui: return "OUI"
        case .portProbe: return "Porta"
        }
    }

    var color: Color {
        switch self {
        case .onvif: return .teal
        case .bonjour: return .blue
        case .oui: return .purple
        case .portProbe: return .orange
        }
    }
}

/// A single detected camera, shown in the Cameras tab.
struct CameraInfo: Identifiable, Hashable {
    let id: String          // MAC (stable identity, matches Host.id)
    var ip: String
    var mac: String
    var vendor: String?
    var hostname: String?
    var detectionSource: CameraDetectionSource
    /// Codec from SDP (JPEG/H264/H265), nil until a snapshot/DESCRIBE runs.
    var codec: String?
    /// Open ports from the probe (554, 3702, 8000, 80, 8080…).
    var openPorts: [UInt16]?
    /// Audit note shown on the card, e.g. "senha padrão (admin:12345)"
    /// when the camera authenticated with a factory-default credential.
    var authNote: String?
    /// ONVIF device service URL learned via WS-Discovery, if any.
    var onvifXAddr: String?
    /// Exact RTSP stream path learned via ONVIF GetStreamUri, if any.
    var rtspPath: String?

    static func == (lhs: CameraInfo, rhs: CameraInfo) -> Bool {
        lhs.id == rhs.id && lhs.ip == rhs.ip && lhs.detectionSource == rhs.detectionSource
            && lhs.codec == rhs.codec && lhs.openPorts == rhs.openPorts
            && lhs.authNote == rhs.authNote && lhs.onvifXAddr == rhs.onvifXAddr
            && lhs.rtspPath == rhs.rtspPath
    }
    func hash(into hasher: inout Hasher) { hasher.combine(id) }
}
