import Testing
import Foundation
@testable import PastoralCore

/// Unit tests for the Lobo-mode captive portal: check recognition and
/// page generation.
@Suite("PortalPage (Lobo mode)")
struct PortalPageTests {

    // MARK: Captive-check recognition

    @Test("recognises Apple and Google captive probes")
    func knownChecks() {
        #expect(PortalPage.isCaptiveCheck(host: "captive.apple.com", path: "/hotspot-detect.html"))
        #expect(PortalPage.isCaptiveCheck(host: "connectivitycheck.google.com", path: "/generate_204"))
        #expect(PortalPage.isCaptiveCheck(host: "connect.google.com", path: "/generate_204"))
        #expect(PortalPage.isCaptiveCheck(host: "clients3.google.com", path: "/generate_204"))
        #expect(PortalPage.isCaptiveCheck(host: "connectivity-check.ubuntu.com", path: "/"))
    }

    @Test("port suffix and query string don't hide a check")
    func normalization() {
        #expect(PortalPage.isCaptiveCheck(
            host: "ConnectivityCheck.Google.com", path: "/generate_204?x=1"))
        #expect(PortalPage.isCaptiveCheck(
            host: "captive.apple.com:80", path: "/hotspot-detect.html"))
    }

    @Test("ordinary sites are not captive checks")
    func notChecks() {
        #expect(!PortalPage.isCaptiveCheck(host: "www.google.com", path: "/search"))
        #expect(!PortalPage.isCaptiveCheck(host: "connectivitycheck.google.com.evil.test",
                                           path: "/generate_204"))
        #expect(!PortalPage.isCaptiveCheck(host: "example.com", path: "/" ))
        #expect(!PortalPage.isCaptiveCheck(host: "", path: "/"))
    }

    // MARK: Page generation

    @Test("page HTML carries message and dark chrome")
    func pageBasics() {
        let html = PortalPage.pageHTML(message: "Tudo certo ✓")
        let lowered = html.lowercased()
        #expect(html.contains("Tudo certo ✓"))
        #expect(lowered.hasPrefix("<!doctype html>"))
        #expect(lowered.contains("viewport"))
        #expect(!lowered.contains("<img"))   // no image → no data URI
    }

    @Test("page embeds the background image as a data URI")
    func pageWithImage() {
        let b64 = Data([0xFF, 0xD8, 0xFF, 0xE0]).base64EncodedString()
        let html = PortalPage.pageHTML(message: "oi", imageBase64: b64)
        #expect(html.contains("data:image/jpeg;base64,\(b64)"))
        #expect(html.lowercased().contains("<img"))
    }

    @Test("user input is HTML-escaped in the page")
    func escapesUserInput() {
        let html = PortalPage.pageHTML(message: "<script>alert('a&b')</script>")
        #expect(html.contains("&lt;script&gt;alert(&#39;a&amp;b&#39;)&lt;/script&gt;"))
        #expect(!html.contains("<script>alert"))
    }
}
