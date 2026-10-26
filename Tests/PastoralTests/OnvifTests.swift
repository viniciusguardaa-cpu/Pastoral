import Testing
import Foundation
@testable import PastoralCore

@Suite("ONVIF discovery")
struct OnvifDiscoveryTests {

    /// A realistic WS-Discovery ProbeMatch (TP-Link VIGI style).
    private let probeMatch = """
    <?xml version="1.0" encoding="UTF-8"?>
    <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
        xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
        xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
        xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
      <soap:Body>
        <d:ProbeMatches>
          <d:ProbeMatch>
            <wsa:EndpointReference>
              <wsa:Address>urn:uuid:3fa1fe68-b915-4053-a3e1-4e57f5aabbcc</wsa:Address>
            </wsa:EndpointReference>
            <d:Types>dn:NetworkVideoTransmitter</d:Types>
            <d:Scopes>onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/name/VIGI%20C300 onvif://www.onvif.org/hardware/C300 onvif://www.onvif.org/location/p%C3%A1tio</d:Scopes>
            <d:XAddrs>http://192.168.1.5:2020/onvif/device_service</d:XAddrs>
            <d:MetadataVersion>1</d:MetadataVersion>
          </d:ProbeMatch>
        </d:ProbeMatches>
      </soap:Body>
    </soap:Envelope>
    """

    @Test func probeMatchParsesXAddrScopesAndEndpoint() {
        let devices = Onvif.parseProbeMatches(probeMatch)
        #expect(devices.count == 1)
        let dev = devices[0]
        #expect(dev.ip == "192.168.1.5")
        #expect(dev.xaddr == "http://192.168.1.5:2020/onvif/device_service")
        #expect(dev.endpoint == "urn:uuid:3fa1fe68-b915-4053-a3e1-4e57f5aabbcc")
        #expect(dev.name == "VIGI C300")
        #expect(dev.hardware == "C300")
        #expect(dev.location == "pátio")
    }

    @Test func probeMatchAcceptsDifferentPrefixes() {
        let xml = """
        <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope">
          <SOAP-ENV:Body><wsdd:ProbeMatches xmlns:wsdd="http://schemas.xmlsoap.org/ws/2005/04/discovery">
            <wsdd:ProbeMatch>
              <wsdd:Types>dn:NetworkVideoTransmitter</wsdd:Types>
              <wsdd:XAddrs>http://10.0.0.44/onvif/device_service http://10.0.0.44:8080/onvif/device_service</wsdd:XAddrs>
            </wsdd:ProbeMatch>
          </wsdd:ProbeMatches></SOAP-ENV:Body>
        </SOAP-ENV:Envelope>
        """
        let devices = Onvif.parseProbeMatches(xml)
        #expect(devices.count == 1)
        #expect(devices[0].xaddr == "http://10.0.0.44/onvif/device_service")
    }

    @Test func probeMatchRejectsNonCameraWSD() {
        // Windows PCs answer WSD probes — they must not become cameras.
        let xml = """
        <e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope">
          <e:Body><d:ProbeMatches xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
            <d:ProbeMatch>
              <d:Types>wsdp:Device pub:Computer</d:Types>
              <d:XAddrs>http://192.168.1.50:5357/abc</d:XAddrs>
            </d:ProbeMatch>
          </d:ProbeMatches></e:Body>
        </e:Envelope>
        """
        #expect(Onvif.parseProbeMatches(xml).isEmpty)
    }

    @Test func mediaXAddrFromCapabilities() {
        let xml = """
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
          <s:Body><tds:GetCapabilitiesResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
            <tds:Capabilities>
              <tt:Media xmlns:tt="http://www.onvif.org/ver10/schema">
                <tt:XAddr>http://192.168.1.5:2020/onvif/media_service</tt:XAddr>
                <tt:StreamingCapabilities><tt:RTPMulticast>false</tt:RTPMulticast></tt:StreamingCapabilities>
              </tt:Media>
            </tds:Capabilities>
          </tds:GetCapabilitiesResponse></s:Body>
        </s:Envelope>
        """
        #expect(Onvif.mediaXAddr(from: xml) == "http://192.168.1.5:2020/onvif/media_service")
    }

    @Test func profileTokensFromGetProfiles() {
        let xml = """
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
          <s:Body><trt:GetProfilesResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl">
            <trt:Profiles token="MainStream" fixed="true"><tt:Name>main</tt:Name></trt:Profiles>
            <trt:Profiles fixed="true" token="SubStream"><tt:Name>sub</tt:Name></trt:Profiles>
          </s:GetProfilesResponse_wait></s:Body>
        </s:Envelope>
        """.replacingOccurrences(of: "_wait", with: "")
        let tokens = Onvif.profileTokens(from: xml)
        #expect(tokens == ["MainStream", "SubStream"])
    }

    @Test func streamURIFromGetStreamUri() {
        let xml = """
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
          <s:Body><trt:GetStreamUriResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl">
            <trt:MediaUri><tt:Uri xmlns:tt="http://www.onvif.org/ver10/schema">rtsp://192.168.1.5:554/stream1</tt:Uri>
            <tt:InvalidAfterConnect>false</tt:InvalidAfterConnect></trt:MediaUri>
          </trt:GetStreamUriResponse></s:Body>
        </s:Envelope>
        """
        #expect(Onvif.streamURI(from: xml) == "rtsp://192.168.1.5:554/stream1")
    }

    @Test func faultReasonExtracted() {
        let xml = """
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>
          <s:Fault><s:Reason><s:Text xml:lang="en">Not authorized</s:Text></s:Reason></s:Fault>
        </s:Body></s:Envelope>
        """
        #expect(Onvif.faultReason(from: xml) == "Not authorized")
    }
}
