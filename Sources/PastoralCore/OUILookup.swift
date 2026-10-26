import Foundation

/// Offline OUI (Organizationally Unique Identifier) vendor lookup.
///
/// The OUI database is generated at build time from the IEEE OUI data
/// (see Scripts/gen-oui.sh) and embedded in the app bundle as oui.json.
/// This class is pure logic over an injected dictionary — testable without
/// the full 40k-entry database.
public struct OUILookup: Sendable {
    /// Maps "AABBCC" (uppercase hex, no separators) → vendor name.
    private let entries: [String: String]

    public init(entries: [String: String]) {
        self.entries = entries
    }

    /// Load from JSON data (format: {"AABBCC": "Vendor, Inc.", ...}).
    public init(jsonData: Data) throws {
        self.entries = try JSONDecoder().decode([String: String].self, from: jsonData)
    }

    /// Look up the vendor for a MAC address.
    /// - Parameter mac: MAC address string (e.g. "aa:bb:cc:dd:ee:ff")
    /// - Returns: vendor name, or nil if unknown.
    public func vendor(forMAC mac: String) -> String? {
        guard mac.count >= 8 else { return nil }
        // Extract first 3 octets, normalize to uppercase hex without separators.
        let cleaned = mac.replacingOccurrences(of: ":", with: "")
            .replacingOccurrences(of: "-", with: "")
        guard cleaned.count >= 6 else { return nil }
        let prefix = String(cleaned.prefix(6)).uppercased()
        return entries[prefix]
    }

    /// Look up the vendor for a MAC address from raw bytes.
    public func vendor(forMACBytes bytes: [UInt8]) -> String? {
        guard bytes.count >= 3 else { return nil }
        let prefix = String(format: "%02X%02X%02X", bytes[0], bytes[1], bytes[2])
        return entries[prefix]
    }
}
