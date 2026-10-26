import Testing
import Foundation
@testable import PastoralCore

/// Unit tests for the intercept decision logic.
@Suite("Intercept decision")
struct InterceptDecisionTests {

    @Test("Selected non-excluded hosts are intercepted")
    func selectedHosts() {
        let hosts = [
            HostInfo(id: "aa:bb:cc:dd:ee:01", ip: "10.0.0.5"),
            HostInfo(id: "aa:bb:cc:dd:ee:02", ip: "10.0.0.6"),
            HostInfo(id: "aa:bb:cc:dd:ee:03", ip: "10.0.0.7")
        ]
        let selected: Set<String> = ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]
        let targets = InterceptDecision.targetsToIntercept(hosts: hosts, selectedIDs: selected)
        #expect(targets.contains("10.0.0.5"))
        #expect(targets.contains("10.0.0.6"))
        #expect(!targets.contains("10.0.0.7"))
    }

    @Test("Excluded hosts are never intercepted")
    func excludedHosts() {
        let hosts = [
            HostInfo(id: "aa:bb:cc:dd:ee:01", ip: "10.0.0.5", isExcluded: true),
            HostInfo(id: "aa:bb:cc:dd:ee:02", ip: "10.0.0.6")
        ]
        let selected: Set<String> = ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]
        let targets = InterceptDecision.targetsToIntercept(hosts: hosts, selectedIDs: selected)
        #expect(!targets.contains("10.0.0.5"))  // excluded
        #expect(targets.contains("10.0.0.6"))
    }

    @Test("shouldIntercept checks selection and exclusion")
    func shouldIntercept() {
        let host = HostInfo(id: "x", ip: "10.0.0.5", isExcluded: false)
        #expect(InterceptDecision.shouldIntercept(host: host, selectedIDs: ["x"]) == true)
        #expect(InterceptDecision.shouldIntercept(host: host, selectedIDs: []) == false)
        let excluded = HostInfo(id: "x", ip: "10.0.0.5", isExcluded: true)
        #expect(InterceptDecision.shouldIntercept(host: excluded, selectedIDs: ["x"]) == false)
    }

    @Test("Empty selection produces no targets")
    func emptySelection() {
        let hosts = [HostInfo(id: "x", ip: "10.0.0.5")]
        let targets = InterceptDecision.targetsToIntercept(hosts: hosts, selectedIDs: [])
        #expect(targets.isEmpty)
    }
}

/// Unit tests for CertificatePlanner (pure logic).
@Suite("Certificate planner")
struct CertificatePlannerTests {

    @Test("CA subject has correct common name")
    func caSubject() {
        let subject = CertificatePlanner.caSubject()
        #expect(subject[kSecOIDCommonName as String] as? String == "Pastoral CA")
        #expect(subject[kSecOIDOrganizationName as String] as? String == "Pastoral")
    }

    @Test("Leaf subject uses SNI as common name")
    func leafSubject() {
        let subject = CertificatePlanner.leafSubject(sni: "example.com")
        #expect(subject[kSecOIDCommonName as String] as? String == "example.com")
    }

    @Test("CA validity is 10 years")
    func caValidity() {
        #expect(CertificatePlanner.caValidity == 10 * 365 * 24 * 3600)
    }

    @Test("Leaf validity is 1 year")
    func leafValidity() {
        #expect(CertificatePlanner.leafValidity == 365 * 24 * 3600)
    }

    @Test("Key tags are stable")
    func keyTags() {
        #expect(CertificatePlanner.caKeyTag == "com.pastoral.ca.key")
        #expect(CertificatePlanner.caCertTag == "com.pastoral.ca.cert")
    }
}
