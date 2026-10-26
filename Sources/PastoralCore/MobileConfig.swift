import Foundation

/// Builds an iOS/macOS `.mobileconfig` Configuration Profile embedding
/// the Pastoral root CA. A cert delivered via a profile is trusted for
/// SSL automatically — unlike a manual cert install, which needs the
/// extra "Certificate Trust Settings" toggle on iOS.
///
/// Caveat (documented in the UI/docs): Safari and WKWebView honor it;
/// native apps using NSURLSession with default handling also trust it,
/// but apps with their own pinning or ATS exceptions may not.
public enum MobileConfig {

    /// Generate a .mobileconfig plist containing `caDER` as a
    /// com.apple.security.root payload.
    public static func make(caDER: Data,
                            name: String = "Pastoral CA",
                            org: String = "Pastoral") -> Data {
        let certUUID = UUID().uuidString.uppercased()
        let profileUUID = UUID().uuidString.uppercased()
        let b64 = caDER.base64EncodedString()
        let plist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" \
        "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>PayloadContent</key>
            <array>
                <dict>
                    <key>PayloadCertificateFileName</key>
                    <string>pastoral-ca.cer</string>
                    <key>PayloadContent</key>
                    <data>\(b64)</data>
                    <key>PayloadDescription</key>
                    <string>Root CA para interceptação TLS do Pastoral (uso autorizado)</string>
                    <key>PayloadDisplayName</key>
                    <string>\(name)</string>
                    <key>PayloadIdentifier</key>
                    <string>com.pastoral.ca.cert</string>
                    <key>PayloadType</key>
                    <string>com.apple.security.root</string>
                    <key>PayloadUUID</key>
                    <string>\(certUUID)</string>
                    <key>PayloadVersion</key>
                    <integer>1</integer>
                </dict>
            </array>
            <key>PayloadDescription</key>
            <string>Instala a CA raiz do Pastoral como confiável.</string>
            <key>PayloadDisplayName</key>
            <string>\(org) Root CA</string>
            <key>PayloadIdentifier</key>
            <string>com.pastoral.ca.profile</string>
            <key>PayloadOrganization</key>
            <string>\(org)</string>
            <key>PayloadRemovalDisallowed</key>
            <false/>
            <key>PayloadType</key>
            <string>Configuration</string>
            <key>PayloadUUID</key>
            <string>\(profileUUID)</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
        </plist>
        """
        return Data(plist.utf8)
    }
}
