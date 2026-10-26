import Foundation
import Security

// MARK: - CA + leaf certificate management
//
// Generates a self-signed root CA on first use, stores the private key in
// the Keychain (kSecAttrIsPermanent), and issues leaf certificates per SNI
// signed by that CA. Leaves are cached on disk. All testable via the pure
// logic in CertificatePlanner; the Keychain/Security framework calls live
// in CAManager.

/// Pure-logic helpers for certificate planning. No I/O, testable.
public enum CertificatePlanner {
    /// Build the certificate subject/issuer for a root CA.
    public static func caSubject(commonName: String = "Pastoral CA",
                                 organization: String = "Pastoral") -> [String: Any] {
        [
            kSecOIDCommonName as String: commonName,
            kSecOIDOrganizationName as String: organization
        ]
    }

    /// Build the certificate subject for a leaf cert for a given SNI.
    public static func leafSubject(sni: String) -> [String: Any] {
        [kSecOIDCommonName as String: sni]
    }

    /// The Keychain service tag for the CA private key.
    public static let caKeyTag = "com.pastoral.ca.key"

    /// The Keychain service tag for the CA certificate.
    public static let caCertTag = "com.pastoral.ca.cert"

    /// Default CA validity in seconds (10 years).
    public static let caValidity: TimeInterval = 10 * 365 * 24 * 3600

    /// Default leaf validity in seconds (1 year).
    public static let leafValidity: TimeInterval = 365 * 24 * 3600

    /// The directory for caching leaf certificates.
    public static let leafCacheDir = "Library/Application Support/Pastoral/leaves"
}

/// Manages the Pastoral CA: generation, storage in Keychain, and leaf
/// certificate issuance. Uses Security.framework (SecCertificateCreateWithData,
/// SecKeyCreateRandomKey, etc.).
public final class CAManager {
    /// The CA certificate data (DER-encoded).
    public private(set) var caCertificate: Data?
    /// The CA private key reference.
    public private(set) var caPrivateKey: SecKey?
    /// The leaf cache directory path.
    public let leafCachePath: String

    public init(leafCachePath: String? = nil) {
        if let path = leafCachePath {
            self.leafCachePath = path
        } else {
            let home = NSHomeDirectory()
            self.leafCachePath = "\(home)/\(CertificatePlanner.leafCacheDir)"
        }
    }

    // MARK: - CA generation

    /// Generate a self-signed root CA if one doesn't exist in the Keychain.
    /// Returns true if the CA was created or already exists.
    public func ensureCA() throws -> Bool {
        // Try to load existing CA from Keychain.
        if let cert = loadCACertificate() {
            caCertificate = cert
            if let key = loadCAPrivateKey() {
                caPrivateKey = key
                return true
            }
        }

        // Generate a new CA key pair.
        let keyAttrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: CertificatePlanner.caKeyTag.data(using: .utf8)!
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(keyAttrs as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw NSError(domain: "CAManager", code: 1, userInfo: [NSLocalizedDescriptionKey: "failed to get public key"])
        }

        // Build a self-signed certificate. We use SecCertificateCreateSelfSignedWithKey
        // (available via the older API) or build a minimal cert manually.
        // On macOS, we can use SecCertificateCreateWithData with a pre-built
        // DER, but building a self-signed cert programmatically requires
        // either the older SecCertificateCreateSelfSignedWithKey (deprecated)
        // or constructing the DER ourselves. We use a simpler approach:
        // generate the cert using the openssl command line (available on macOS).
        caPrivateKey = privateKey

        // Generate the CA certificate via openssl (reliable on macOS).
        let certData = try generateCACertificate(privateKey: privateKey, publicKey: publicKey)
        caCertificate = certData

        // Store the CA certificate in the Keychain.
        try storeCACertificate(certData)

        return true
    }

    /// Generate a self-signed CA certificate using openssl.
    private func generateCACertificate(privateKey: SecKey, publicKey: SecKey) throws -> Data {
        // Export the private key to PEM (via SecKeyCopyExternalRepresentation).
        var error: Unmanaged<CFError>?
        guard let keyData = SecKeyCopyExternalRepresentation(privateKey, &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }

        // Write the private key to a temp file in PKCS#1 PEM format.
        let tmpDir = NSTemporaryDirectory()
        let keyPath = "\(tmpDir)pastoral-ca-key-\(UUID().uuidString).pem"
        let pemKey = "-----BEGIN PRIVATE KEY-----\n" +
                     keyData.base64EncodedString(options: [.lineLength64Characters]) +
                     "\n-----END PRIVATE KEY-----\n"
        try pemKey.data(using: .utf8)?.write(to: URL(fileURLWithPath: keyPath))

        let certPath = "\(tmpDir)pastoral-ca-cert-\(UUID().uuidString).der"

        // Use openssl to generate a self-signed CA cert.
        let cmd = """
        openssl req -x509 -new -key "\(keyPath)" -out "\(certPath)" -outform DER \
            -days 3650 -subj "/CN=Pastoral CA/O=Pastoral" \
            -addext "basicConstraints=critical,CA:TRUE" \
            -addext "keyUsage=critical,keyCertSign,cRLSign" 2>&1
        """
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/sh")
        p.arguments = ["-c", cmd]
        p.standardOutput = FileHandle.standardError
        p.standardError = FileHandle.standardError
        try p.run()
        p.waitUntilExit()

        defer {
            try? FileManager.default.removeItem(atPath: keyPath)
            try? FileManager.default.removeItem(atPath: certPath)
        }

        guard p.terminationStatus == 0,
              let certData = try? Data(contentsOf: URL(fileURLWithPath: certPath)) else {
            throw NSError(domain: "CAManager", code: 2, userInfo: [NSLocalizedDescriptionKey: "openssl failed to generate CA cert"])
        }
        return certData
    }

    // MARK: - Leaf certificate issuance

    /// Issue a leaf certificate for a given SNI, signed by the CA. Cached
    /// on disk. Returns the leaf certificate data (DER-encoded) and the
    /// private key.
    public func issueLeaf(for sni: String) throws -> (cert: Data, key: SecKey) {
        // The SNI comes from LAN clients and is interpolated into a
        // /bin/sh command — only plain hostname characters pass.
        try Self.validateSNI(sni)

        // Check the cache.
        let cachePath = "\(leafCachePath)/\(sni.replacingOccurrences(of: "/", with: "_")).der"
        let keyCachePath = "\(leafCachePath)/\(sni.replacingOccurrences(of: "/", with: "_")).key"

        if FileManager.default.fileExists(atPath: cachePath),
           FileManager.default.fileExists(atPath: keyCachePath),
           leafCacheValid(cachePath: cachePath),
           let certData = try? Data(contentsOf: URL(fileURLWithPath: cachePath)),
           let keyData = try? Data(contentsOf: URL(fileURLWithPath: keyCachePath)) {
            var error: Unmanaged<CFError>?
            if let key = SecKeyCreateWithData(keyData as CFData,
                                               [kSecAttrKeyType as String: kSecAttrKeyTypeRSA] as CFDictionary,
                                               &error) {
                return (certData, key)
            }
        }

        // Ensure CA exists.
        if caCertificate == nil || caPrivateKey == nil {
            _ = try ensureCA()
        }
        guard let caKey = caPrivateKey else {
            throw NSError(domain: "CAManager", code: 3, userInfo: [NSLocalizedDescriptionKey: "no CA private key"])
        }

        // Generate a new leaf key pair.
        let keyAttrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048
        ]
        var error: Unmanaged<CFError>?
        guard let leafKey = SecKeyCreateRandomKey(keyAttrs as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }

        // Export keys and generate the leaf cert via openssl.
        guard let leafKeyData = SecKeyCopyExternalRepresentation(leafKey, nil) as Data?,
              let caKeyData = SecKeyCopyExternalRepresentation(caKey, nil) as Data? else {
            throw NSError(domain: "CAManager", code: 4, userInfo: [NSLocalizedDescriptionKey: "failed to export keys"])
        }

        let tmpDir = NSTemporaryDirectory()
        let leafKeyPath = "\(tmpDir)pastoral-leaf-key-\(UUID().uuidString).pem"
        let caKeyPath = "\(tmpDir)pastoral-ca-key-\(UUID().uuidString).pem"
        let caCertPath = "\(tmpDir)pastoral-ca-cert-\(UUID().uuidString).pem"
        let leafCertPath = "\(tmpDir)pastoral-leaf-cert-\(UUID().uuidString).der"
        let leafCsrPath = "\(tmpDir)pastoral-leaf-csr-\(UUID().uuidString).csr"

        let pemLeafKey = "-----BEGIN PRIVATE KEY-----\n" +
                         leafKeyData.base64EncodedString(options: [.lineLength64Characters]) +
                         "\n-----END PRIVATE KEY-----\n"
        let pemCaKey = "-----BEGIN PRIVATE KEY-----\n" +
                       caKeyData.base64EncodedString(options: [.lineLength64Characters]) +
                       "\n-----END PRIVATE KEY-----\n"
        let pemCaCert = "-----BEGIN CERTIFICATE-----\n" +
                        (caCertificate ?? Data()).base64EncodedString(options: [.lineLength64Characters]) +
                        "\n-----END CERTIFICATE-----\n"

        try pemLeafKey.data(using: .utf8)?.write(to: URL(fileURLWithPath: leafKeyPath))
        try pemCaKey.data(using: .utf8)?.write(to: URL(fileURLWithPath: caKeyPath))
        try pemCaCert.data(using: .utf8)?.write(to: URL(fileURLWithPath: caCertPath))

        defer {
            for path in [leafKeyPath, caKeyPath, caCertPath, leafCertPath, leafCsrPath] {
                try? FileManager.default.removeItem(atPath: path)
            }
        }

        // Generate CSR, then sign with CA.
        let cmd = """
        openssl req -new -key "\(leafKeyPath)" -out "\(leafCsrPath)" \
            -subj "/CN=\(sni)" 2>&1 && \
        openssl x509 -req -in "\(leafCsrPath)" -CA "\(caCertPath)" -CAkey "\(caKeyPath)" \
            -CAcreateserial -out "\(leafCertPath)" -outform DER -days 365 \
            -extfile <(echo "subjectAltName=DNS:\(sni)") 2>&1
        """
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/sh")
        p.arguments = ["-c", cmd]
        p.standardOutput = FileHandle.standardError
        p.standardError = FileHandle.standardError
        try p.run()
        p.waitUntilExit()

        guard p.terminationStatus == 0,
              let certData = try? Data(contentsOf: URL(fileURLWithPath: leafCertPath)) else {
            throw NSError(domain: "CAManager", code: 5, userInfo: [NSLocalizedDescriptionKey: "openssl failed to generate leaf cert"])
        }

        // Cache the cert and key, with an expiry sidecar so the next
        // session regenerates instead of serving a stale (or revoked)
        // leaf forever.
        try? FileManager.default.createDirectory(atPath: leafCachePath, withIntermediateDirectories: true)
        try? certData.write(to: URL(fileURLWithPath: cachePath))
        try? leafKeyData.write(to: URL(fileURLWithPath: keyCachePath))
        try? Self.isoFormatter().string(
            from: Date().addingTimeInterval(CertificatePlanner.leafValidity)
        ).write(to: URL(fileURLWithPath: cachePath + ".exp"),
                atomically: true, encoding: .utf8)

        return (certData, leafKey)
    }

    /// Built per call — cheap here (cache checks only), and avoids a
    /// shared non-Sendable formatter under Swift 6 strict concurrency.
    private static func isoFormatter() -> ISO8601DateFormatter {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }

    /// Cache entry is valid while its `.exp` sidecar is in the future.
    /// Entries written before sidecars existed get regenerated once.
    private func leafCacheValid(cachePath: String) -> Bool {
        guard let iso = try? String(contentsOf: URL(fileURLWithPath: cachePath + ".exp"),
                                    encoding: .utf8),
              let expiry = Self.isoFormatter().date(from: iso),
              Date.now < expiry else { return false }
        return true
    }

    /// Reject SNIs that could escape the openssl invocation they are
    /// interpolated into: allow RFC-952/3986 hostname characters only.
    static func validateSNI(_ sni: String) throws {
        let allowed = CharacterSet(charactersIn:
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        guard !sni.isEmpty, sni.count <= 253,
              sni.unicodeScalars.allSatisfy(allowed.contains) else {
            throw NSError(domain: "CAManager", code: 6,
                          userInfo: [NSLocalizedDescriptionKey: "SNI inválido: \(sni)"])
        }
    }

    // MARK: - SecIdentity for TLS termination

    /// Cache of SecIdentity per SNI — building one involves openssl +
    /// keychain import, so it's done once per host.
    private var identityCache: [String: SecIdentity] = [:]
    private let identityLock = NSLock()

    /// Build a SecIdentity (leaf cert + private key) for TLS termination.
    /// The leaf is exported as a PKCS#12 via openssl and imported
    /// memory-only — nothing is persisted to the user keychain.
    public func secIdentity(for sni: String) throws -> SecIdentity {
        identityLock.lock()
        defer { identityLock.unlock() }

        if let cached = identityCache[sni] { return cached }

        let (certData, leafKey) = try issueLeaf(for: sni)

        var error: Unmanaged<CFError>?
        guard let keyData = SecKeyCopyExternalRepresentation(leafKey, &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }

        // openssl pkcs12 -export needs PEM inputs.
        let pemKey = "-----BEGIN PRIVATE KEY-----\n" +
                     keyData.base64EncodedString(options: [.lineLength64Characters]) +
                     "\n-----END PRIVATE KEY-----\n"
        let pemCert = "-----BEGIN CERTIFICATE-----\n" +
                      certData.base64EncodedString(options: [.lineLength64Characters]) +
                      "\n-----END CERTIFICATE-----\n"

        let tmpDir = NSTemporaryDirectory()
        let keyPath = "\(tmpDir)pastoral-id-key-\(UUID().uuidString).pem"
        let certPath = "\(tmpDir)pastoral-id-cert-\(UUID().uuidString).pem"
        let p12Path = "\(tmpDir)pastoral-id-\(UUID().uuidString).p12"
        try pemKey.data(using: .utf8)?.write(to: URL(fileURLWithPath: keyPath))
        try pemCert.data(using: .utf8)?.write(to: URL(fileURLWithPath: certPath))

        defer {
            for p in [keyPath, certPath, p12Path] {
                try? FileManager.default.removeItem(atPath: p)
            }
        }

        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/sh")
        p.arguments = ["-c", """
        openssl pkcs12 -export -inkey "\(keyPath)" -in "\(certPath)" \
            -out "\(p12Path)" -passout pass: -name "pastoral-leaf" 2>&1
        """]
        p.standardOutput = FileHandle.standardError
        p.standardError = FileHandle.standardError
        try p.run()
        p.waitUntilExit()

        guard p.terminationStatus == 0,
              let p12Data = try? Data(contentsOf: URL(fileURLWithPath: p12Path)) else {
            throw NSError(domain: "CAManager", code: 8,
                          userInfo: [NSLocalizedDescriptionKey: "openssl pkcs12 export failed"])
        }

        // Import memory-only — the identity never lands in a keychain.
        var items: CFArray?
        var options: [String: Any] = [kSecImportExportPassphrase as String: ""]
        if #available(macOS 15.0, *) {
            options[kSecImportToMemoryOnly as String] = true
        }
        let status = SecPKCS12Import(p12Data as CFData, options as CFDictionary, &items)
        guard status == errSecSuccess,
              let arr = items as? [[String: Any]],
              let item = arr.first,
              let identity = item[kSecImportItemIdentity as String] else {
            throw NSError(domain: "CAManager", code: 9,
                          userInfo: [NSLocalizedDescriptionKey: "SecPKCS12Import failed: \(status)"])
        }
        let secIdentity = identity as! SecIdentity

        identityCache[sni] = secIdentity
        return secIdentity
    }

    // MARK: - Keychain storage

    private func storeCACertificate(_ data: Data) throws {
        // Remove any existing cert with our tag.
        let query: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrApplicationTag as String: CertificatePlanner.caCertTag.data(using: .utf8)!
        ]
        SecItemDelete(query as CFDictionary)

        // Add the new cert.
        let attrs: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecValueData as String: data,
            kSecAttrApplicationTag as String: CertificatePlanner.caCertTag.data(using: .utf8)!
        ]
        let status = SecItemAdd(attrs as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw NSError(domain: "CAManager", code: 6, userInfo: [NSLocalizedDescriptionKey: "SecItemAdd failed: \(status)"])
        }
    }

    private func loadCACertificate() -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrApplicationTag as String: CertificatePlanner.caCertTag.data(using: .utf8)!,
            kSecReturnData as String: true
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else { return nil }
        return data
    }

    private func loadCAPrivateKey() -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrApplicationTag as String: CertificatePlanner.caKeyTag.data(using: .utf8)!,
            kSecReturnRef as String: true
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else { return nil }
        return (item as! SecKey)
    }

    // MARK: - Trust management

    /// Install the CA into the system trust store via `security add-trusted-cert`.
    /// Requires root (called through the helper or PrivilegedInstaller).
    public func installTrust(certPath: String) -> Bool {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        p.arguments = ["add-trusted-cert", "-d", "-r", "trustRoot",
                       "-k", "/Library/Keychains/System.keychain", certPath]
        do { try p.run(); p.waitUntilExit() } catch { return false }
        return p.terminationStatus == 0
    }

    /// Remove the CA from the system trust store.
    public func removeTrust(certPath: String) -> Bool {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        p.arguments = ["remove-trusted-cert", "-d", certPath]
        do { try p.run(); p.waitUntilExit() } catch { return false }
        return p.terminationStatus == 0
    }

    /// Export the CA certificate to a temp file (for trust installation).
    public func exportCAToTemp() throws -> String {
        if caCertificate == nil {
            _ = try ensureCA()
        }
        guard let certData = caCertificate else {
            throw NSError(domain: "CAManager", code: 7, userInfo: [NSLocalizedDescriptionKey: "no CA certificate"])
        }
        let path = "\(NSTemporaryDirectory())pastoral-ca-\(UUID().uuidString).der"
        try certData.write(to: URL(fileURLWithPath: path))
        return path
    }

    /// Check if the CA is trusted in the system keychain.
    public func isTrusted() -> Bool {
        // This is a heuristic: check if the cert is in the system keychain
        // trust store. A full check requires evaluating the trust chain.
        guard let cert = caCertificate else { return false }
        let secCert = SecCertificateCreateWithData(nil, cert as CFData)
        guard secCert != nil else { return false }
        // Evaluate trust.
        var trust: SecTrust?
        let policy = SecPolicyCreateBasicX509()
        let status = SecTrustCreateWithCertificates([secCert!] as CFArray, policy, &trust)
        guard status == errSecSuccess, let trust else { return false }
        var error: CFError?
        let result = SecTrustEvaluateWithError(trust, &error)
        return result
    }
}
