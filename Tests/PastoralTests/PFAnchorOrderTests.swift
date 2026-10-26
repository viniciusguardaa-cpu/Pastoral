import Testing
import Foundation
@testable import PastoralCore

/// Unit tests for the canonical pf.conf anchor ordering that keeps the
/// selective/dummynet rules evaluating BEFORE the sheep wildcard rdr.
@Suite("PFAnchorManager ordered anchors (Lobo prerequisite)")
struct PFAnchorOrderTests {

    private let kill      = #"anchor "com.pastoral/kill""#
    private let selective = #"anchor "com.pastoral/selective""#
    private let dummynet  = #"dummynet-anchor "com.pastoral/dummynet""#
    private let sheep     = #"anchor "com.pastoral/sheep""#

    @Test("ensureSheepAnchor appends at end when pf.conf is clean")
    func cleanAppend() {
        let out = PFAnchorManager.ensureSheepAnchor(in: "set skip on lo0\nscrub\n")
        #expect(out.hasSuffix("\(sheep)\n"))
        #expect(out.contains("set skip on lo0"))
        #expect(out.contains("scrub"))
    }

    @Test("sheep is repositioned after selective+dummynet when added first")
    func reorderBehindSelective() {
        // The historical bug: sheep installed before selective existed,
        // so selective landed AFTER it and cuts stopped biting.
        let broken = "set skip on lo0\n\(sheep)\nmatch in all\n"
        let out = PFAnchorManager.orderedPastoralAnchors(
            in: broken, ensuring: [selective, dummynet])
        let lines = out.components(separatedBy: "\n")
        let s = lines.firstIndex(of: selective)!
        let d = lines.firstIndex(of: dummynet)!
        let p = lines.firstIndex(of: sheep)!
        #expect(s < d)
        #expect(d < p)
        #expect(out.contains("match in all"))
    }

    @Test("existing anchors are deduped and canonicalised in place")
    func canonicaliseDuplicates() {
        let messy = """
        set skip on lo0
        \(sheep)
        \(kill)
        \(selective)
        \(selective)
        \(dummynet)
        antonate
        """
        let out = PFAnchorManager.orderedPastoralAnchors(in: messy, ensuring: [])
        let lines = out.components(separatedBy: "\n")
        #expect(out.components(separatedBy: kill).count - 1 == 1)
        #expect(out.components(separatedBy: selective).count - 1 == 1)
        #expect(out.components(separatedBy: dummynet).count - 1 == 1)
        #expect(out.components(separatedBy: sheep).count - 1 == 1)
        let k = lines.firstIndex(of: kill)!
        let s = lines.firstIndex(of: selective)!
        let d = lines.firstIndex(of: dummynet)!
        let p = lines.firstIndex(of: sheep)!
        #expect(k < s && s < d && d < p)
        // First pastoral line was sheep; the block must sit where it was,
        // keeping 'antonate' after it.
        let a = lines.firstIndex(of: "antonate")!
        #expect(p < a)
        #expect(out.hasPrefix("set skip on lo0\n"))
    }

    @Test("ensureSheepAnchor after a Lobo deployment keeps order stable")
    func sheepJoiningLater() {
        let base = "set skip on lo0\n\(kill)\n\(selective)\n\(dummynet)\n"
        let out = PFAnchorManager.ensureSheepAnchor(in: base)
        let lines = out.split(separator: "\n").map(String.init)
        let k = lines.firstIndex(of: kill)!
        let s = lines.firstIndex(of: selective)!
        let d = lines.firstIndex(of: dummynet)!
        let p = lines.firstIndex(of: sheep)!
        #expect(k < s && s < d && d < p)
    }

    @Test("running the normalisation twice is a no-op")
    func idempotent() {
        let once = PFAnchorManager.orderedPastoralAnchors(
            in: "\(sheep)\n\(selective)\n", ensuring: [dummynet])
        let twice = PFAnchorManager.orderedPastoralAnchors(
            in: once, ensuring: [dummynet])
        #expect(once == twice)
    }

    @Test("file without any pastoral lines gets ensured block at EOF")
    func ensureOnCleanFile() {
        let out = PFAnchorManager.orderedPastoralAnchors(
            in: "set skip on lo0\n", ensuring: [selective, dummynet])
        let lines = out.split(separator: "\n").map(String.init)
        #expect(lines.last == dummynet)
        #expect(lines[lines.count - 2] == selective)
        #expect(lines.first == "set skip on lo0")
    }
}
