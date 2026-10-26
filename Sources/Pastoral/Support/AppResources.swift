import Foundation

enum AppResources {
    /// SwiftPM's generated accessor assumes a command-line layout. Packaged
    /// applications keep their resource bundle in Contents/Resources.
    static let bundle: Bundle = {
        if let url = Bundle.main.url(forResource: "Pastoral_Pastoral", withExtension: "bundle"),
           let bundle = Bundle(url: url) { return bundle }
        return Bundle.module
    }()
}
