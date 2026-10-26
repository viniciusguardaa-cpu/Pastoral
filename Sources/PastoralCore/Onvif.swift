import Foundation

// MARK: - ONVIF WS-Discovery + media service helpers (pure logic, testable)
//
// ONVIF cameras answer a WS-Discovery Probe multicast to
// 239.255.255.250:3702 (UDP) with a ProbeMatch containing the device
// service URL (XAddrs) and scopes (name/hardware/location/type).
// With credentials, the media service returns the exact RTSP stream
// URI via GetProfiles + GetStreamUri — eliminating path guessing.
//
// XML parsing is deliberately regex/scan-based: camera SOAP responses
// use wildly inconsistent namespace prefixes (wsa/wsdd/tds/trt/tt…)
// and we only need a handful of leaf values.

/// A camera discovered via WS-Discovery.
public struct OnvifDevice: Equatable, Sendable {
    public var ip: String        // host extracted from XAddrs (fallback: UDP sender)
    public var xaddr: String     // ONVIF device service URL
    public var endpoint: String? // EndpointReference (stable per-device UUID)
    public var name: String?     // onvif://…/name/… scope
    public var hardware: String? // onvif://…/hardware/… scope
    public var location: String? // onvif://…/location/… scope

    public init(ip: String, xaddr: String, endpoint: String? = nil,
                name: String? = nil, hardware: String? = nil,
                location: String? = nil) {
        self.ip = ip
        self.xaddr = xaddr
        self.endpoint = endpoint
        self.name = name
        self.hardware = hardware
        self.location = location
    }
}

public enum Onvif {

    // MARK: - WS-Discovery

    /// WS-Discovery Probe message for the multicast group.
    /// `types` empty = generic probe (matches everything; non-camera
    /// responders are filtered out by parseProbeMatches).
    public static func probeXML(types: String = "dn:NetworkVideoTransmitter",
                                messageID: String = UUID().uuidString) -> String {
        let typesXML = types.isEmpty ? "" : "<d:Types>\(types)</d:Types>"
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            + "<e:Envelope xmlns:e=\"http://www.w3.org/2003/05/soap-envelope\""
            + " xmlns:w=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\""
            + " xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\""
            + " xmlns:dn=\"http://www.onvif.org/ver10/network/wsdl\">"
            + "<e:Header><w:MessageID>urn:uuid:\(messageID)</w:MessageID>"
            + "<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>"
            + "<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>"
            + "</e:Header><e:Body><d:Probe>\(typesXML)</d:Probe></e:Body></e:Envelope>"
    }

    /// Parse all ProbeMatch elements from a WS-Discovery response.
    /// Only returns entries that look like ONVIF/video devices —
    /// Windows PCs and printers answer WSD probes too.
    public static func parseProbeMatches(_ xml: String) -> [OnvifDevice] {
        sections("ProbeMatch", in: xml).compactMap { match in
            guard let xaddrList = firstTag("XAddrs", in: match) else { return nil }
            let xaddr = xaddrList.split(whereSeparator: \.isWhitespace)
                .map(String.init)
                .first { $0.lowercased().hasPrefix("http://") }
            guard let xaddr else { return nil }

            let scopes = firstTag("Scopes", in: match) ?? ""
            let types = firstTag("Types", in: match) ?? ""
            let blob = "\(xaddr) \(scopes) \(types)".lowercased()
            guard blob.contains("onvif") || blob.contains("videoencoder")
                    || blob.contains("networkvideotransmitter") else { return nil }

            let scopeParts = scopes.split(whereSeparator: \.isWhitespace).map(String.init)
            func scope(_ key: String) -> String? {
                scopeParts.first { $0.lowercased().contains("/\(key)/") }
                    .flatMap { $0.components(separatedBy: "/\(key)/").last }
                    .flatMap { $0.removingPercentEncoding }
            }
            let epr = section("EndpointReference", in: match)
                .flatMap { firstTag("Address", in: $0) }
            let host = URL(string: xaddr)?.host ?? ""
            return OnvifDevice(ip: host, xaddr: xaddr, endpoint: epr,
                               name: scope("name"), hardware: scope("hardware"),
                               location: scope("location"))
        }
    }

    // MARK: - SOAP bodies

    public static let getCapabilitiesXML =
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
        + " xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\"><s:Body>"
        + "<tds:GetCapabilities><tds:Category>Media</tds:Category></tds:GetCapabilities>"
        + "</s:Body></s:Envelope>"

    public static let getProfilesXML =
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
        + " xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\"><s:Body>"
        + "<trt:GetProfiles/></s:Body></s:Envelope>"

    public static func getStreamUriXML(profileToken: String) -> String {
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
        + " xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\""
        + " xmlns:tt=\"http://www.onvif.org/ver10/schema\"><s:Body>"
        + "<trt:GetStreamUri><trt:StreamSetup>"
        + "<tt:Stream>RTP-Unicast</tt:Stream>"
        + "<tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport>"
        + "</trt:StreamSetup><trt:ProfileToken>\(profileToken)</trt:ProfileToken>"
        + "</trt:GetStreamUri></s:Body></s:Envelope>"
    }

    // MARK: - Response parsing

    /// Media service XAddr from a GetCapabilities response — may live on
    /// a different port/path than the device service.
    public static func mediaXAddr(from xml: String) -> String? {
        guard let media = section("Media", in: xml) else { return nil }
        return firstTag("XAddr", in: media)
    }

    /// Profile tokens from a GetProfiles response (trt:Profiles elements).
    public static func profileTokens(from xml: String) -> [String] {
        let pattern = "<(?:[A-Za-z0-9_]+:)?Profiles\\s[^>]*?\\btoken=\"([^\"]+)\""
        guard let re = try? NSRegularExpression(pattern: pattern) else { return [] }
        let range = NSRange(xml.startIndex..., in: xml)
        return re.matches(in: xml, range: range).compactMap {
            Range($0.range(at: 1), in: xml).map { String(xml[$0]) }
        }
    }

    /// RTSP URI from a GetStreamUri response.
    public static func streamURI(from xml: String) -> String? {
        let scope = section("MediaUri", in: xml) ?? xml
        guard let uri = firstTag("Uri", in: scope),
              uri.lowercased().hasPrefix("rtsp") else { return nil }
        return uri
    }

    /// SOAP Fault reason text, if the response is a fault.
    public static func faultReason(from xml: String) -> String? {
        guard let fault = section("Fault", in: xml) else { return nil }
        return firstTag("Text", in: fault) ?? firstTag("faultstring", in: fault)
    }

    // MARK: - Tiny XML scanners

    /// All element bodies named `name` (any namespace prefix).
    static func sections(_ name: String, in xml: String) -> [String] {
        let pattern = "<(?:[A-Za-z0-9_]+:)?\(name)\\b[^>]*>(.*?)</(?:[A-Za-z0-9_]+:)?\(name)>"
        guard let re = try? NSRegularExpression(
            pattern: pattern, options: [.dotMatchesLineSeparators]) else { return [] }
        let range = NSRange(xml.startIndex..., in: xml)
        return re.matches(in: xml, range: range).compactMap {
            Range($0.range(at: 1), in: xml).map { String(xml[$0]) }
        }
    }

    /// First element body named `name` (any namespace prefix).
    static func section(_ name: String, in xml: String) -> String? {
        sections(name, in: xml).first
    }

    /// Text content of the first `<*:name>text</*:name>` element
    /// (attributes on the open tag are ignored).
    static func firstTag(_ name: String, in xml: String) -> String? {
        let pattern = "<(?:[A-Za-z0-9_]+:)?\(name)(?:\\s[^>]*)?>([^<]*)</(?:[A-Za-z0-9_]+:)?\(name)>"
        guard let re = try? NSRegularExpression(pattern: pattern),
              let m = re.firstMatch(in: xml, range: NSRange(xml.startIndex..., in: xml)),
              let r = Range(m.range(at: 1), in: xml) else { return nil }
        let text = String(xml[r]).trimmingCharacters(in: .whitespacesAndNewlines)
        return text.isEmpty ? nil : text
    }
}
