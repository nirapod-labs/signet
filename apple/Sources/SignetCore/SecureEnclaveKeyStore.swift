// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import Foundation
import LocalAuthentication
import Security

/// Secure Enclave-backed P-256 key store for iOS and macOS.
///
/// Keys are created non-exportable in the Secure Enclave. There is no export
/// path: the outputs are a handle, a public key (separate surface), a signature,
/// and attestation, never private-key bytes. Secure Enclave creation failure
/// raises `unavailableTier`; the store never falls back to software.
public struct SecureEnclaveKeyStore: Sendable {
    /// Namespaces the application tag so Signet keys do not collide with other
    /// keychain items in the app's access group.
    private static let tagPrefix = "nirapod.signet."

    /// Serializes auth-gated signing so two biometric prompts never contend for
    /// the key. A reference type; copies of this value-type store share it.
    private let signGate = SignGate()

    public init() {}

    /// Generates a non-exportable P-256 key in the Secure Enclave, gated by the
    /// spec's access-control policy.
    ///
    /// - Returns: the key handle and a tier report read from what was created
    ///   (`achieved`, `evidence`, `meetsFloor`, `authEnforced`).
    /// - Throws: `keyAlreadyExists` if the alias is taken; `unavailableTier` if
    ///   the Secure Enclave cannot create the key; `hardwareError` if the
    ///   access-control object cannot be built.
    public func generateKey(_ spec: KeySpec) throws -> (KeyHandle, SecurityTierReport) {
        guard !exists(alias: spec.alias) else {
            throw SignetError.keyAlreadyExists
        }

        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            Self.accessFlags(for: spec.accessControl),
            nil
        ) else {
            throw SignetError.hardwareError
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag(for: spec.alias),
                kSecAttrAccessControl as String: access,
                kSecUseDataProtectionKeychain as String: true,
            ],
        ]

        var cfError: Unmanaged<CFError>?
        guard SecKeyCreateRandomKey(attributes as CFDictionary, &cfError) != nil else {
            // Never fall back to software. Map the failure cause honestly.
            let code = (cfError?.takeRetainedValue()).map { CFErrorGetCode($0) } ?? 0
            throw Self.mapCreationFailure(code: code)
        }

        let report = SecurityTierReport(
            achieved: .secureEnclave,
            requested: spec.tierPolicy,
            meetsFloor: spec.tierPolicy.isMet(
                by: .secureEnclave,
                platformStrongest: .secureEnclave
            ),
            evidence: .seTokenPresent,
            authEnforced: Self.authClass(for: spec.accessControl),
            invalidated: false
        )
        return (KeyHandle(alias: spec.alias), report)
    }

    /// Returns the public key for a handle. `rawX962` is the native Secure
    /// Enclave output (`0x04 || X || Y`); `spki` wraps it in a
    /// SubjectPublicKeyInfo. There is no matching private-key accessor.
    ///
    /// - Throws: `notFound` if no key exists for the alias; `hardwareError` if
    ///   the public key cannot be read.
    public func getPublicKey(
        _ handle: KeyHandle,
        format: PublicKey.Format = .rawX962
    ) throws -> PublicKey {
        let key = try fetchKey(alias: handle.alias)
        guard let publicKey = SecKeyCopyPublicKey(key),
              let raw = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            throw SignetError.hardwareError
        }
        switch format {
        case .rawX962:
            return PublicKey(format: .rawX962, bytes: raw)
        case .spki:
            return PublicKey(format: .spki, bytes: Self.spki(fromRawX962: raw))
        }
    }

    /// Signs a 32-byte digest with the key and encodes per `options`. A
    /// wrong-length digest is rejected with `invalidArgument` before any
    /// keychain access.
    ///
    /// - Throws: `invalidArgument` if the digest is not exactly 32 bytes;
    ///   `notFound` if no key exists; `hardwareError` on a signing failure. For
    ///   a gated key, an authentication cancel, an auth failure, or a
    ///   re-enrollment invalidation also surfaces as `hardwareError`; `sign`
    ///   discards the underlying error and does not distinguish them.
    public func sign(
        _ handle: KeyHandle,
        digest: Data,
        options: SignOptions = SignOptions()
    ) throws -> Data {
        guard digest.count == 32 else {
            throw SignetError.invalidArgument
        }
        let key = try fetchKey(alias: handle.alias)
        guard let der = SecKeyCreateSignature(
            key,
            .ecdsaSignatureDigestX962SHA256,
            digest as CFData,
            nil
        ) as Data? else {
            throw SignetError.hardwareError
        }
        switch options.encoding {
        case .der:
            return der
        case .rawRS:
            guard let raw = Self.derToRawRS(der) else {
                throw SignetError.hardwareError
            }
            return raw
        }
    }

    /// Signs a 32-byte digest with an auth-gated key, presenting the biometric
    /// prompt through the Secure Enclave and suspending until the user responds.
    /// Auth-gated signing is serialized: a second call issued while a prompt is
    /// still outstanding is rejected with `authInProgress`. The digest guard and
    /// the `options` encoding match the silent `sign`.
    ///
    /// Apple exposes no dedicated invalidation code, so a key invalidated by a
    /// biometric re-enrollment surfaces here as `authFailed` (or `notFound`), not
    /// `keyInvalidated`; this weaker probing is contract-allowed and mirrors the
    /// silent path and `getSecurityTier`.
    ///
    /// - Throws: `invalidArgument` if the digest is not 32 bytes; `authInProgress`
    ///   if a gated sign is already in progress; `notFound` if no key exists;
    ///   `userCanceled` if the user dismissed the prompt; `authFailed` if
    ///   authentication failed; `authContextRequired` if no prompt could be
    ///   presented; `hardwareError` on any other signing failure.
    public func sign(
        _ handle: KeyHandle,
        digest: Data,
        prompt: AuthPrompt,
        options: SignOptions = SignOptions()
    ) async throws -> Data {
        guard digest.count == 32 else {
            throw SignetError.invalidArgument
        }
        guard signGate.tryEnter() else {
            throw SignetError.authInProgress
        }
        defer { signGate.exit() }
        // SecKeyCreateSignature blocks the calling thread while the Enclave
        // presents the prompt; Apple directs this off the main thread.
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(with: Result {
                    try self.gatedSign(handle, digest: digest, prompt: prompt, options: options)
                })
            }
        }
    }

    /// The blocking body of the gated `sign`: attaches an `LAContext` carrying the
    /// prompt's reason to the key fetch, so the Enclave presents that reason when
    /// the signature triggers authentication, then maps a failure through
    /// `mapGatedSignFailure`. `kSecUseOperationPrompt` is deprecated; the reason is
    /// carried on the context via `kSecUseAuthenticationContext`.
    private func gatedSign(
        _ handle: KeyHandle,
        digest: Data,
        prompt: AuthPrompt,
        options: SignOptions
    ) throws -> Data {
        let context = LAContext()
        context.localizedReason = Self.reason(for: prompt)
        context.localizedCancelTitle = prompt.negativeButtonText
        let key = try fetchKey(alias: handle.alias, context: context)
        var cfError: Unmanaged<CFError>?
        guard let der = SecKeyCreateSignature(
            key,
            .ecdsaSignatureDigestX962SHA256,
            digest as CFData,
            &cfError
        ) as Data? else {
            throw Self.mapGatedSignFailure(cfError?.takeRetainedValue())
        }
        switch options.encoding {
        case .der:
            return der
        case .rawRS:
            guard let raw = Self.derToRawRS(der) else {
                throw SignetError.hardwareError
            }
            return raw
        }
    }

    /// The single reason line for the biometric prompt: the title, with the
    /// subtitle appended below it when present. Apple's prompt has no separate
    /// subtitle field.
    static func reason(for prompt: AuthPrompt) -> String {
        guard let subtitle = prompt.subtitle, !subtitle.isEmpty else {
            return prompt.title
        }
        return "\(prompt.title)\n\(subtitle)"
    }

    /// Maps a gated-sign failure to the closed error set. A dismissed prompt is
    /// `userCanceled`; a failed authentication (and, indistinguishably on Apple, a
    /// re-enrollment-invalidated key) is `authFailed`; a prompt that could not be
    /// presented is `authContextRequired`. The Security framework surfaces OSStatus
    /// codes and LocalAuthentication its own `LAError` codes; both are mapped, and
    /// every other code is `hardwareError`.
    static func mapGatedSignFailure(_ error: CFError?) -> SignetError {
        guard let error else { return .hardwareError }
        let domain = CFErrorGetDomain(error) as String
        let code = CFErrorGetCode(error)
        if domain == LAErrorDomain {
            switch code {
            case LAError.Code.userCancel.rawValue,
                 LAError.Code.appCancel.rawValue,
                 LAError.Code.systemCancel.rawValue:
                return .userCanceled
            case LAError.Code.authenticationFailed.rawValue,
                 LAError.Code.biometryLockout.rawValue:
                return .authFailed
            case LAError.Code.notInteractive.rawValue,
                 LAError.Code.invalidContext.rawValue,
                 LAError.Code.passcodeNotSet.rawValue,
                 LAError.Code.biometryNotAvailable.rawValue,
                 LAError.Code.biometryNotEnrolled.rawValue:
                return .authContextRequired
            default:
                return .hardwareError
            }
        }
        switch code {
        case Int(errSecUserCanceled):
            return .userCanceled
        case Int(errSecAuthFailed):
            return .authFailed
        case Int(errSecInteractionNotAllowed):
            return .authContextRequired
        default:
            return .hardwareError
        }
    }

    /// Re-reads the tier of an existing key. Does not throw on an invalidated
    /// key. `requested` and `authEnforced` come back nil (unreadable on Apple);
    /// `invalidated` is `false` here. The Secure Enclave has no non-prompting
    /// invalidation probe: re-enrollment invalidation surfaces only as an
    /// ordinary authentication failure at signing time, with no dedicated code,
    /// and `sign` discards the underlying error and maps every failure to
    /// `hardwareError`, never `keyInvalidated`. This weaker probing is
    /// contract-allowed. `meetsFloor` is true against every policy (the Secure
    /// Enclave is Apple's strongest tier).
    ///
    /// - Throws: `notFound` if no key exists for the alias.
    public func getSecurityTier(_ handle: KeyHandle) throws -> SecurityTierReport {
        guard exists(alias: handle.alias) else {
            throw SignetError.notFound
        }
        return SecurityTierReport(
            achieved: .secureEnclave,
            requested: nil,
            meetsFloor: true,
            evidence: .seTokenPresent,
            authEnforced: nil,
            invalidated: false
        )
    }

    /// Returns the attestation for a key. The Secure Enclave has no per-key
    /// hardware attestation; this is always `format = none` with an empty
    /// chain, for any live-or-invalidated key.
    ///
    /// - Throws: `notFound` if no key exists for the alias.
    public func getAttestation(_ handle: KeyHandle) throws -> AttestationResult {
        guard exists(alias: handle.alias) else {
            throw SignetError.notFound
        }
        return AttestationResult(format: .none)
    }

    /// Reports whether a key exists for the alias without materializing a handle.
    public func exists(alias: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag(for: alias),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnRef as String: false,
        ]
        return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
    }

    /// Deletes the key for the alias. Idempotent: a missing key is a success.
    ///
    /// - Throws: `hardwareError` if the key store rejects the delete for any
    ///   reason other than the key being absent.
    public func delete(alias: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag(for: alias),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecUseDataProtectionKeychain as String: true,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SignetError.hardwareError
        }
    }

    /// Fetches the private key reference for an alias. Internal by design: the
    /// private key is used in-process and never returned to a caller; there is
    /// no public accessor for it.
    ///
    /// - Throws: `notFound` if no key exists; `hardwareError` on any other
    ///   keychain failure. A non-nil `context` attaches an authentication context
    ///   so a later gated operation on the key presents that context's prompt.
    func fetchKey(alias: String, context: LAContext? = nil) throws -> SecKey {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag(for: alias),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnRef as String: true,
        ]
        if let context {
            query[kSecUseAuthenticationContext as String] = context
        }
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            throw status == errSecItemNotFound ? SignetError.notFound : SignetError.hardwareError
        }
        guard let item, CFGetTypeID(item) == SecKeyGetTypeID() else {
            throw SignetError.hardwareError
        }
        return item as! SecKey
    }

    /// The `SecAccessControlCreateFlags` for a policy. `.privateKeyUsage` is
    /// required for a Secure Enclave key. `invalidateOnBiometricEnrollment`
    /// selects `.biometryCurrentSet` (invalidated on re-enrollment) over
    /// `.biometryAny`.
    static func accessFlags(for policy: AccessControlPolicy) -> SecAccessControlCreateFlags {
        let biometric: SecAccessControlCreateFlags =
            policy.invalidateOnBiometricEnrollment ? .biometryCurrentSet : .biometryAny
        switch policy.authRequirement {
        case .none:
            return .privateKeyUsage
        case .biometricOnly:
            return [.privateKeyUsage, biometric]
        case .biometricOrDeviceCredential:
            return [.privateKeyUsage, biometric, .or, .devicePasscode]
        }
    }

    /// The `AuthClass` a policy produces on Apple. Apple exposes no read-back of
    /// a created `SecAccessControl`; creation is all-or-nothing (the key is
    /// returned only if built with these flags, never a silent downgrade). The
    /// reported class is the class the key was created with.
    static func authClass(for policy: AccessControlPolicy) -> AuthClass {
        switch policy.authRequirement {
        case .none:
            return .none
        case .biometricOnly:
            return .biometricOnly
        case .biometricOrDeviceCredential:
            return .biometricOrDeviceCredential
        }
    }

    /// Wraps a P-256 X9.63 public key (`0x04 || X || Y`) in a DER
    /// SubjectPublicKeyInfo. The 26-byte prefix is the fixed id-ecPublicKey with
    /// prime256v1 and the BIT STRING header for the 65-byte point.
    static func spki(fromRawX962 raw: Data) -> Data {
        let header: [UInt8] = [
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
            0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
            0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
            0x42, 0x00,
        ]
        return Data(header) + raw
    }

    /// Converts a DER ECDSA signature (`SEQUENCE { INTEGER r, INTEGER s }`) to
    /// the fixed 64-byte `r || s` form, each a 32-byte big-endian integer.
    /// Returns nil if the DER is malformed or a component exceeds 32 bytes.
    static func derToRawRS(_ der: Data) -> Data? {
        let bytes = [UInt8](der)
        var i = 0
        guard bytes.count >= 2, bytes[i] == 0x30, bytes[i + 1] & 0x80 == 0 else { return nil }
        let seqLen = Int(bytes[i + 1])
        i += 2
        guard i + seqLen == bytes.count else { return nil }
        guard let r = Self.readInteger(bytes, &i), let s = Self.readInteger(bytes, &i) else {
            return nil
        }
        guard i == bytes.count, let r32 = Self.leftPad32(r), let s32 = Self.leftPad32(s) else {
            return nil
        }
        return Data(r32 + s32)
    }

    /// Reads one DER INTEGER at `i`, advancing `i`, and returns its big-endian
    /// bytes with the positive-padding `0x00` stripped. Nil if malformed.
    private static func readInteger(_ bytes: [UInt8], _ i: inout Int) -> [UInt8]? {
        guard i < bytes.count, bytes[i] == 0x02, i + 1 < bytes.count, bytes[i + 1] & 0x80 == 0 else {
            return nil
        }
        let len = Int(bytes[i + 1])
        i += 2
        guard len > 0, i + len <= bytes.count else { return nil }
        var value = Array(bytes[i..<(i + len)])
        i += len
        while value.count > 1 && value[0] == 0x00 { value.removeFirst() }
        return value
    }

    /// Left-pads a big-endian integer to 32 bytes. Nil if it exceeds 32.
    private static func leftPad32(_ value: [UInt8]) -> [UInt8]? {
        guard value.count <= 32 else { return nil }
        return Array(repeating: 0, count: 32 - value.count) + value
    }

    /// Maps a `SecKeyCreateRandomKey` failure code to the closed error set.
    /// `errSecInteractionNotAllowed` (locked device) is `hardwareError`, a
    /// transient platform failure, not a tier absence. `errSecDuplicateItem` is
    /// `keyAlreadyExists`. Every other code is `unavailableTier`; never software.
    static func mapCreationFailure(code: Int) -> SignetError {
        switch code {
        case Int(errSecInteractionNotAllowed):
            return .hardwareError
        case Int(errSecDuplicateItem):
            return .keyAlreadyExists
        default:
            return .unavailableTier
        }
    }

    /// Application tag for an alias: the library namespace prefix plus the alias.
    private func tag(for alias: String) -> Data {
        Data((Self.tagPrefix + alias).utf8)
    }
}

/// Serializes auth-gated signing: a second gated `sign` issued while a prompt is
/// still outstanding is rejected, so two biometric prompts never contend for the
/// key. The Android core enforces the same rule; the mechanism differs, the
/// contract does not. `@unchecked Sendable` because the lock, not the type system,
/// guards the single mutable flag.
private final class SignGate: @unchecked Sendable {
    private let lock = NSLock()
    private var busy = false

    /// Enters the gate if it is free, reporting whether entry succeeded.
    func tryEnter() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if busy { return false }
        busy = true
        return true
    }

    /// Leaves the gate, admitting the next gated sign.
    func exit() {
        lock.lock()
        defer { lock.unlock() }
        busy = false
    }
}
