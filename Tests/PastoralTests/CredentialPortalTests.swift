import Testing
import Foundation
@testable import PastoralCore

/// Unit tests for the fake-login portal: form-body parsing (percent + '+'
/// decoding, hidden page field), HTML escaping, and endpoint constants.
@Suite("CredentialPortal (fake login)")
struct CredentialPortalTests {

    @Test("a normal form submission parses all fields")
    func normal() {
        let body = "user=vic%40mail.com&pass=azul+123&page=iCloud".data(using: .utf8)!
        let r = CredentialPortal.parseFormBody(body)
        #expect(r?.user == "vic@mail.com")
        #expect(r?.pass == "azul 123")
        #expect(r?.page == "iCloud")
    }

    @Test("percent escapes decode to raw bytes, including UTF-8")
    func utf8() {
        // "señal" percent-encoded: s e %C3%B1 a l
        let body = "user=&pass=se%C3%B1al&x=1".data(using: .utf8)!
        let r = CredentialPortal.parseFormBody(body)
        #expect(r?.pass == "señal")
        #expect(r?.user == "")
    }

    @Test("values with equals signs survive (split on first '=' only)")
    func equalsInValue() {
        let body = "pass=a=b=c&user=u".data(using: .utf8)!
        let r = CredentialPortal.parseFormBody(body)
        #expect(r?.pass == "a=b=c")
    }

    @Test("keys are decoded too")
    func encodedKey() {
        let body = "us%65r=x&pass=p".data(using: .utf8)!  // %65 = 'e'
        #expect(CredentialPortal.parseFormBody(body)?.user == "x")
    }

    @Test("neither user nor pass present → nil, not a bogus capture")
    func noCreds() {
        #expect(CredentialPortal.parseFormBody("page=iCloud".data(using: .utf8)!) == nil)
        #expect(CredentialPortal.parseFormBody(Data()) == nil)
    }

    @Test("a lone '=' and empty pairs don't break the parser")
    func degenerate() {
        let r = CredentialPortal.parseFormBody("&=&&user=".data(using: .utf8)!)
        #expect(r != nil)
        if let r { #expect(r.user == "" && r.pass == "") }
        let r2 = CredentialPortal.parseFormBody("=x&user=%3D".data(using: .utf8)!)
        #expect(r2?.user == "=")
    }

    @Test("mangled percent sequences fall through as literal characters")
    func mangled() {
        #expect(CredentialPortal.percentDecode("%ZZ") == "%ZZ")
        #expect(CredentialPortal.percentDecode("100%") == "100%")
        #expect(CredentialPortal.percentDecode("a+%2Bb") == "a +b")
        #expect(CredentialPortal.percentDecode("") == "")
    }

    @Test("escape covers the five HTML metacharacters only")
    func escaping() {
        #expect(CredentialPortal.escape("<a href='x' & y>") == "&lt;a href=&#39;x&#39; &amp; y&gt;")
        #expect(!CredentialPortal.escape("abc").contains("&"))
    }

    @Test("the login page posts to the cred endpoint and carries the CA link")
    func pageShape() {
        for style in CredentialPortal.PageStyle.allCases {
            let html = CredentialPortal.loginHTML(style: style,
                                                  showCALink: true)
                .replacingOccurrences(of: "\n", with: "")
            #expect(html.contains(CredentialPortal.credPath), "style \(style.rawValue)")
            #expect(html.contains("user"), "style \(style.rawValue)")
            #expect(html.contains("pass"), "style \(style.rawValue)")
            #expect(html.contains(CredentialPortal.caProfilePath), "style \(style.rawValue)")
        }
        let noCA = CredentialPortal.loginHTML(style: .icloud, showCALink: false)
        #expect(!noCA.contains(CredentialPortal.caProfilePath))
    }

    @Test("endpoints are absolute paths under the portal namespace")
    func paths() {
        #expect(CredentialPortal.credPath == "/__pastoral__/cred")
        #expect(CredentialPortal.caProfilePath == "/__pastoral__/ca.mobileconfig")
    }

    @Test("CapturedCredential round-trips through Codable")
    func codable() {
        let c = CapturedCredential(user: "u", pass: "p", ssid: "Casa",
                                   sourceIP: "10.0.0.5", page: "iCloud",
                                   timestamp: Date(timeIntervalSince1970: 1_700_000_000))
        let data = try! JSONEncoder().encode(c)
        let back = try! JSONDecoder().decode(CapturedCredential.self, from: data)
        #expect(back.user == c.user && back.pass == c.pass)
        #expect(back.sourceIP == c.sourceIP)
        #expect(back.timestamp.timeIntervalSince1970 == 1_700_000_000)
        #expect(!back.summary.isEmpty)
    }
}
