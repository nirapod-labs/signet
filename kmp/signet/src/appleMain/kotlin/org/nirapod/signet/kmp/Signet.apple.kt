// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

@file:OptIn(ExperimentalForeignApi::class)

package org.nirapod.signet.kmp

import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.CValuesRef
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.MemScope
import kotlinx.cinterop.alloc
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.allocArrayOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.IntVar
import kotlinx.cinterop.get
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.value
import platform.CoreFoundation.CFDataCreate
import platform.CoreFoundation.CFDataGetBytePtr
import platform.CoreFoundation.CFDataGetLength
import platform.CoreFoundation.CFDataRef
import platform.CoreFoundation.CFDictionaryAddValue
import platform.CoreFoundation.CFDictionaryCreateMutable
import platform.CoreFoundation.CFDictionaryRef
import platform.CoreFoundation.CFErrorGetCode
import platform.CoreFoundation.CFErrorRefVar
import platform.CoreFoundation.CFGetTypeID
import platform.CoreFoundation.CFNumberCreate
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.CFStringRef
import platform.CoreFoundation.CFTypeRef
import platform.CoreFoundation.CFTypeRefVar
import platform.CoreFoundation.kCFAllocatorDefault
import platform.CoreFoundation.kCFBooleanFalse
import platform.CoreFoundation.kCFBooleanTrue
import platform.CoreFoundation.kCFNumberIntType
import platform.CoreFoundation.kCFTypeDictionaryKeyCallBacks
import platform.CoreFoundation.kCFTypeDictionaryValueCallBacks
import platform.Security.SecAccessControlCreateFlags
import platform.Security.SecAccessControlCreateWithFlags
import platform.Security.SecItemCopyMatching
import platform.Security.SecItemDelete
import platform.Security.SecKeyCopyExternalRepresentation
import platform.Security.SecKeyCopyPublicKey
import platform.Security.SecKeyCreateRandomKey
import platform.Security.SecKeyCreateSignature
import platform.Security.SecKeyGetTypeID
import platform.Security.SecKeyRef
import platform.Security.errSecDuplicateItem
import platform.Security.errSecInteractionNotAllowed
import platform.Security.errSecItemNotFound
import platform.Security.errSecSuccess
import platform.Security.kSecAttrAccessControl
import platform.Security.kSecAttrAccessibleWhenUnlockedThisDeviceOnly
import platform.Security.kSecAttrApplicationTag
import platform.Security.kSecAttrIsPermanent
import platform.Security.kSecAttrKeySizeInBits
import platform.Security.kSecAttrKeyType
import platform.Security.kSecAttrKeyTypeECSECPrimeRandom
import platform.Security.kSecAttrTokenID
import platform.Security.kSecAttrTokenIDSecureEnclave
import platform.Security.kSecClass
import platform.Security.kSecClassKey
import platform.Security.kSecKeyAlgorithmECDSASignatureDigestX962SHA256
import platform.Security.kSecPrivateKeyAttrs
import platform.Security.kSecReturnRef
import platform.Security.kSecUseDataProtectionKeychain
import platform.Security.kSecAccessControlBiometryAny
import platform.Security.kSecAccessControlBiometryCurrentSet
import platform.Security.kSecAccessControlDevicePasscode
import platform.Security.kSecAccessControlOr
import platform.Security.kSecAccessControlPrivateKeyUsage
import platform.Security.kSecUseAuthenticationContext
import platform.Security.errSecAuthFailed
import platform.Security.errSecUserCanceled
import kotlinx.cinterop.CPointed
import kotlinx.cinterop.interpretCPointer
import kotlinx.cinterop.interpretObjCPointerOrNull
import kotlinx.cinterop.objcPtr
import platform.Foundation.NSError
import platform.LocalAuthentication.LAContext
import platform.LocalAuthentication.LAErrorAppCancel
import platform.LocalAuthentication.LAErrorAuthenticationFailed
import platform.LocalAuthentication.LAErrorBiometryLockout
import platform.LocalAuthentication.LAErrorBiometryNotAvailable
import platform.LocalAuthentication.LAErrorBiometryNotEnrolled
import platform.LocalAuthentication.LAErrorDomain
import platform.LocalAuthentication.LAErrorInvalidContext
import platform.LocalAuthentication.LAErrorNotInteractive
import platform.LocalAuthentication.LAErrorPasscodeNotSet
import platform.LocalAuthentication.LAErrorSystemCancel
import platform.LocalAuthentication.LAErrorUserCancel
import kotlin.concurrent.AtomicInt
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Apple `actual`, shared across the iOS and macOS targets. Re-implements
 * the Secure Enclave path over Security.framework in Kotlin/Native, faithful to the
 * reviewed Apple Swift core.
 *
 * Keys are created non-exportable in the Secure Enclave. No key material crosses
 * this boundary and there is no export path: the outputs are a handle, a public
 * key, a signature, an attestation, and a tier report, never private-key bytes.
 * Secure Enclave creation failure raises [SignetErrorCode.unavailableTier]; the
 * store never falls back to software.
 */
public actual class Signet {
    private val store = SecureEnclaveKeyStore()

    public actual fun generateKey(spec: KeySpec): KeyResult = store.generateKey(spec)

    public actual fun getPublicKey(handle: KeyHandle, format: PublicKey.Format): PublicKey =
        store.getPublicKey(handle, format)

    public actual fun sign(handle: KeyHandle, digest: ByteArray, options: SignOptions): ByteArray =
        store.sign(handle, digest, options)

    public actual suspend fun sign(
        handle: KeyHandle,
        digest: ByteArray,
        authContext: AuthContext,
        options: SignOptions,
    ): ByteArray = store.gatedSign(handle, digest, authContext, options)

    public actual fun getSecurityTier(handle: KeyHandle): SecurityTierReport =
        store.getSecurityTier(handle)

    public actual fun getAttestation(handle: KeyHandle): AttestationResult =
        store.getAttestation(handle)

    public actual fun exists(alias: String): Boolean = store.exists(alias)

    public actual fun delete(alias: String) {
        store.delete(alias)
    }
}

/** Namespaces the application tag under the Signet library prefix. */
private const val TAG_PREFIX = "nirapod.signet."

/**
 * Secure Enclave-backed P-256 key store. The private key is used in-process and
 * never returned; the surface exposes only the handle, public key, signature,
 * attestation, and tier report.
 */
internal class SecureEnclaveKeyStore {

    private val signGate = SignGate()

    /** Generates a non-exportable P-256 key in the Secure Enclave, gated by [spec]'s policy. */
    fun generateKey(spec: KeySpec): KeyResult {
        if (exists(spec.alias)) throw SignetException(SignetErrorCode.keyAlreadyExists)
        return memScoped {
            val access = SecAccessControlCreateWithFlags(
                null,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                accessFlags(spec.accessControl),
                null,
            ) ?: throw SignetException(SignetErrorCode.hardwareError)
            defer { CFRelease(access) }

            val privateAttrs = cfDictionaryOf(
                kSecAttrIsPermanent to kCFBooleanTrue,
                kSecAttrApplicationTag to cfData(tag(spec.alias)),
                kSecAttrAccessControl to access,
                kSecUseDataProtectionKeychain to kCFBooleanTrue,
            )
            val attributes = cfDictionaryOf(
                kSecAttrKeyType to kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeySizeInBits to cfNumber(256),
                kSecAttrTokenID to kSecAttrTokenIDSecureEnclave,
                kSecPrivateKeyAttrs to privateAttrs,
            )

            val error = alloc<CFErrorRefVar>()
            val key = SecKeyCreateRandomKey(attributes, error.ptr)
            if (key == null) {
                // Never fall back to software.
                val code = error.value?.let { cfError ->
                    val c = CFErrorGetCode(cfError).convert<Long>()
                    CFRelease(cfError)
                    c
                } ?: 0L
                throw SignetException(mapCreationFailure(code))
            }
            CFRelease(key)

            val report = SecurityTierReport(
                achieved = SecurityLevel.secureEnclave,
                requested = spec.tierPolicy,
                meetsFloor = spec.tierPolicy.isMet(SecurityLevel.secureEnclave, SecurityLevel.secureEnclave),
                evidence = TierEvidence.seTokenPresent,
                authEnforced = authClass(spec.accessControl),
                invalidated = false,
            )
            KeyResult(KeyHandle(spec.alias), report)
        }
    }

    /** Returns the public key for a handle. There is no matching private-key accessor. */
    fun getPublicKey(handle: KeyHandle, format: PublicKey.Format): PublicKey = memScoped {
        val key = fetchKey(handle.alias)
        defer { CFRelease(key) }
        val publicKey = SecKeyCopyPublicKey(key)
            ?: throw SignetException(SignetErrorCode.hardwareError)
        defer { CFRelease(publicKey) }
        val raw = SecKeyCopyExternalRepresentation(publicKey, null)
            ?: throw SignetException(SignetErrorCode.hardwareError)
        defer { CFRelease(raw) }
        val rawBytes = cfDataToByteArray(raw)
        when (format) {
            PublicKey.Format.rawX962 -> PublicKey(PublicKey.Format.rawX962, rawBytes)
            PublicKey.Format.spki -> PublicKey(PublicKey.Format.spki, spkiFromRawX962(rawBytes))
        }
    }

    /**
     * Signs a 32-byte digest and encodes per [options]. A wrong-length digest is
     * rejected with [SignetErrorCode.invalidArgument] before any keychain access.
     * This is the silent path for a key with no presence check; a gated key is
     * signed through the auth-gated overload.
     */
    fun sign(handle: KeyHandle, digest: ByteArray, options: SignOptions): ByteArray {
        if (digest.size != 32) throw SignetException(SignetErrorCode.invalidArgument)
        return memScoped {
            val key = fetchKey(handle.alias)
            defer { CFRelease(key) }
            signWithKey(key, digest, options)
        }
    }

    /**
     * Signs a 32-byte digest with an auth-gated key, off the main thread. The
     * digest guard precedes the gate. A second gated sign issued while a prompt is
     * outstanding fails [SignetErrorCode.authInProgress]; [SignGate] serializes the
     * path.
     */
    suspend fun gatedSign(
        handle: KeyHandle,
        digest: ByteArray,
        authContext: AuthContext,
        options: SignOptions,
    ): ByteArray {
        if (digest.size != 32) throw SignetException(SignetErrorCode.invalidArgument)
        if (!signGate.tryEnter()) throw SignetException(SignetErrorCode.authInProgress)
        try {
            return withContext(Dispatchers.Default) {
                blockingGatedSign(handle, digest, authContext, options)
            }
        } finally {
            signGate.exit()
        }
    }

    /**
     * The blocking gated-sign body. The prompt reaches the Enclave through an
     * [LAContext] attached to the key fetch.
     */
    private fun blockingGatedSign(
        handle: KeyHandle,
        digest: ByteArray,
        authContext: AuthContext,
        options: SignOptions,
    ): ByteArray = memScoped {
        val laContext = LAContext()
        laContext.localizedReason = gatedReason(authContext)
        laContext.localizedCancelTitle = authContext.negativeButtonText
        val key = fetchKey(handle.alias, laContext)
        defer { CFRelease(key) }
        val error = alloc<CFErrorRefVar>()
        val der = SecKeyCreateSignature(
            key,
            kSecKeyAlgorithmECDSASignatureDigestX962SHA256,
            cfData(digest),
            error.ptr,
        )
        if (der == null) {
            val cfError = error.value
            val code = mapGatedSignFailure(cfError?.let { interpretObjCPointerOrNull<NSError>(it.rawValue) })
            cfError?.let { CFRelease(it) }
            throw SignetException(code)
        }
        defer { CFRelease(der) }
        val derBytes = cfDataToByteArray(der)
        when (options.encoding) {
            SignOptions.Encoding.der -> derBytes
            SignOptions.Encoding.rawRS -> derToRawRS(derBytes)
                ?: throw SignetException(SignetErrorCode.hardwareError)
        }
    }

    /** Re-reads the tier of an existing key. `requested` and `authEnforced` are unreadable on Apple and come back null. */
    fun getSecurityTier(handle: KeyHandle): SecurityTierReport {
        if (!exists(handle.alias)) throw SignetException(SignetErrorCode.notFound)
        return SecurityTierReport(
            achieved = SecurityLevel.secureEnclave,
            requested = null,
            meetsFloor = true,
            evidence = TierEvidence.seTokenPresent,
            authEnforced = null,
            invalidated = false,
        )
    }

    /** The Secure Enclave has no per-key attestation: always `none` with an empty chain. */
    fun getAttestation(handle: KeyHandle): AttestationResult {
        if (!exists(handle.alias)) throw SignetException(SignetErrorCode.notFound)
        return AttestationResult(AttestationResult.Format.none)
    }

    /** Reports whether a key exists for the alias without materializing a handle. */
    fun exists(alias: String): Boolean = memScoped {
        val query = cfDictionaryOf(
            kSecClass to kSecClassKey,
            kSecAttrApplicationTag to cfData(tag(alias)),
            kSecAttrKeyType to kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrTokenID to kSecAttrTokenIDSecureEnclave,
            kSecUseDataProtectionKeychain to kCFBooleanTrue,
            kSecReturnRef to kCFBooleanFalse,
        )
        SecItemCopyMatching(query, null) == errSecSuccess
    }

    /** Deletes the key for the alias. Idempotent: a missing key is a success. */
    fun delete(alias: String) {
        memScoped {
            val query = cfDictionaryOf(
                kSecClass to kSecClassKey,
                kSecAttrApplicationTag to cfData(tag(alias)),
                kSecAttrKeyType to kSecAttrKeyTypeECSECPrimeRandom,
                kSecUseDataProtectionKeychain to kCFBooleanTrue,
            )
            val status = SecItemDelete(query)
            if (status != errSecSuccess && status != errSecItemNotFound) {
                throw SignetException(SignetErrorCode.hardwareError)
            }
        }
    }

    /**
     * Fetches the private-key reference for an alias. The reference is used
     * in-process and never returned to a caller.
     */
    private fun MemScope.fetchKey(alias: String, authContext: LAContext? = null): SecKeyRef {
        val pairs = mutableListOf<Pair<CFStringRef?, CFTypeRef?>>(
            kSecClass to kSecClassKey,
            kSecAttrApplicationTag to cfData(tag(alias)),
            kSecAttrKeyType to kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrTokenID to kSecAttrTokenIDSecureEnclave,
            kSecUseDataProtectionKeychain to kCFBooleanTrue,
            kSecReturnRef to kCFBooleanTrue,
        )
        if (authContext != null) {
            // The dictionary retains the context; the local reference keeps it alive.
            pairs.add(kSecUseAuthenticationContext to interpretCPointer<CPointed>(authContext.objcPtr()))
        }
        val query = cfDictionaryOf(*pairs.toTypedArray())
        val result = alloc<CFTypeRefVar>()
        val status = SecItemCopyMatching(query, result.ptr)
        if (status != errSecSuccess) {
            throw SignetException(
                if (status == errSecItemNotFound) SignetErrorCode.notFound else SignetErrorCode.hardwareError,
            )
        }
        val item = result.value ?: throw SignetException(SignetErrorCode.hardwareError)
        if (CFGetTypeID(item) != SecKeyGetTypeID()) throw SignetException(SignetErrorCode.hardwareError)
        return item.reinterpret()
    }
}

// --- Security.framework helpers (internal for host tests) ---

/** Signs [digest] with an already-resolved [key] and encodes per [options]. */
internal fun MemScope.signWithKey(key: SecKeyRef, digest: ByteArray, options: SignOptions): ByteArray {
    val der = SecKeyCreateSignature(
        key,
        kSecKeyAlgorithmECDSASignatureDigestX962SHA256,
        cfData(digest),
        null,
    ) ?: throw SignetException(SignetErrorCode.hardwareError)
    defer { CFRelease(der) }
    val derBytes = cfDataToByteArray(der)
    return when (options.encoding) {
        SignOptions.Encoding.der -> derBytes
        SignOptions.Encoding.rawRS -> derToRawRS(derBytes)
            ?: throw SignetException(SignetErrorCode.hardwareError)
    }
}

/** Builds a CFDictionary with the type callbacks, released at scope exit. The callbacks are mandatory. */
internal fun MemScope.cfDictionaryOf(vararg pairs: Pair<CFStringRef?, CFTypeRef?>): CFDictionaryRef {
    val dict = CFDictionaryCreateMutable(
        kCFAllocatorDefault,
        pairs.size.convert(),
        kCFTypeDictionaryKeyCallBacks.ptr,
        kCFTypeDictionaryValueCallBacks.ptr,
    ) ?: throw SignetException(SignetErrorCode.hardwareError)
    for ((key, value) in pairs) CFDictionaryAddValue(dict, key, value)
    defer { CFRelease(dict) }
    return dict
}

/** Wraps a [ByteArray] as a CFData, released at scope exit. */
internal fun MemScope.cfData(bytes: ByteArray): CFDataRef {
    // allocArrayOf on an empty array is undefined in Kotlin/Native; a one-byte
    // buffer read with length 0 yields an empty CFData without dereferencing it.
    val buffer = if (bytes.isEmpty()) allocArray<ByteVar>(1) else allocArrayOf(bytes)
    val data = CFDataCreate(kCFAllocatorDefault, buffer.reinterpret(), bytes.size.convert())
        ?: throw SignetException(SignetErrorCode.hardwareError)
    defer { CFRelease(data) }
    return data
}

/** Wraps an [Int] as a CFNumber, released at scope exit. */
internal fun MemScope.cfNumber(value: Int): CFTypeRef {
    val holder = alloc<IntVar>()
    holder.value = value
    val number = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, holder.ptr)
        ?: throw SignetException(SignetErrorCode.hardwareError)
    defer { CFRelease(number) }
    return number
}

/** Copies a CFData's bytes into a [ByteArray]. */
internal fun cfDataToByteArray(data: CFDataRef): ByteArray {
    val length: Int = CFDataGetLength(data).convert()
    if (length == 0) return ByteArray(0)
    val pointer = CFDataGetBytePtr(data) ?: return ByteArray(0)
    return ByteArray(length) { pointer[it].toByte() }
}

// --- Pure codec and policy mapping (no Security calls; fully host-testable) ---

/** The application tag for an alias: the library namespace prefix plus the alias. */
internal fun tag(alias: String): ByteArray = (TAG_PREFIX + alias).encodeToByteArray()

/**
 * The `SecAccessControlCreateFlags` for a policy. `privateKeyUsage` is required
 * for a Secure Enclave key. `invalidateOnBiometricEnrollment` selects
 * `biometryCurrentSet` (invalidated on re-enrollment) over `biometryAny`.
 */
internal fun accessFlags(policy: AccessControlPolicy): SecAccessControlCreateFlags {
    val biometric =
        if (policy.invalidateOnBiometricEnrollment) kSecAccessControlBiometryCurrentSet
        else kSecAccessControlBiometryAny
    return when (policy.authRequirement) {
        AuthRequirement.none -> kSecAccessControlPrivateKeyUsage
        AuthRequirement.biometricOnly -> kSecAccessControlPrivateKeyUsage or biometric
        AuthRequirement.biometricOrDeviceCredential ->
            kSecAccessControlPrivateKeyUsage or biometric or kSecAccessControlOr or kSecAccessControlDevicePasscode
    }
}

/** The [AuthClass] a policy produces. Apple creation is all-or-nothing; the reported class is the created one. */
internal fun authClass(policy: AccessControlPolicy): AuthClass = when (policy.authRequirement) {
    AuthRequirement.none -> AuthClass.none
    AuthRequirement.biometricOnly -> AuthClass.biometricOnly
    AuthRequirement.biometricOrDeviceCredential -> AuthClass.biometricOrDeviceCredential
}

/**
 * Wraps a P-256 X9.63 public key (`0x04 || X || Y`) in a DER SubjectPublicKeyInfo.
 * The 26-byte prefix is the fixed id-ecPublicKey with prime256v1 and the BIT
 * STRING header for the 65-byte point.
 */
internal fun spkiFromRawX962(raw: ByteArray): ByteArray {
    val header = byteArrayOf(
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86.toByte(),
        0x48, 0xce.toByte(), 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
        0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x03, 0x01, 0x07, 0x03,
        0x42, 0x00,
    )
    return header + raw
}

/**
 * Converts a DER ECDSA signature (`SEQUENCE { INTEGER r, INTEGER s }`) to the
 * fixed 64-byte `r || s` form, each a 32-byte big-endian integer. Returns null if
 * the DER is malformed or a component exceeds 32 bytes.
 */
internal fun derToRawRS(der: ByteArray): ByteArray? {
    if (der.size < 2 || der[0] != 0x30.toByte() || (der[1].toInt() and 0x80) != 0) return null
    val seqLen = der[1].toInt() and 0xFF
    if (2 + seqLen != der.size) return null
    val (r, afterR) = readInteger(der, 2) ?: return null
    val (s, afterS) = readInteger(der, afterR) ?: return null
    if (afterS != der.size) return null
    val r32 = leftPad32(r) ?: return null
    val s32 = leftPad32(s) ?: return null
    return r32 + s32
}

/**
 * Reads one DER INTEGER at [start] and returns its big-endian bytes (with the
 * positive-padding `0x00` stripped) paired with the index past it. Null if malformed.
 */
private fun readInteger(bytes: ByteArray, start: Int): Pair<ByteArray, Int>? {
    var i = start
    if (i >= bytes.size || bytes[i] != 0x02.toByte()) return null
    if (i + 1 >= bytes.size || (bytes[i + 1].toInt() and 0x80) != 0) return null
    val length = bytes[i + 1].toInt() and 0xFF
    i += 2
    if (length <= 0 || i + length > bytes.size) return null
    var value = bytes.copyOfRange(i, i + length)
    i += length
    var offset = 0
    while (offset < value.size - 1 && value[offset] == 0x00.toByte()) offset++
    if (offset > 0) value = value.copyOfRange(offset, value.size)
    return value to i
}

/** Left-pads a big-endian integer to 32 bytes. Null if it exceeds 32. */
private fun leftPad32(value: ByteArray): ByteArray? {
    if (value.size > 32) return null
    if (value.size == 32) return value
    return ByteArray(32 - value.size) + value
}

/**
 * Maps a `SecKeyCreateRandomKey` failure code to the closed error set.
 * `errSecInteractionNotAllowed` (locked device) is a transient hardware failure,
 * not a tier absence. `errSecDuplicateItem` is `keyAlreadyExists`. Every other
 * code is `unavailableTier`; never software.
 */
internal fun mapCreationFailure(code: Long): SignetErrorCode = when (code) {
    errSecInteractionNotAllowed.convert<Long>() -> SignetErrorCode.hardwareError
    errSecDuplicateItem.convert<Long>() -> SignetErrorCode.keyAlreadyExists
    else -> SignetErrorCode.unavailableTier
}

/** The prompt reason line: the title, with the subtitle appended below when present. */
internal fun gatedReason(authContext: AuthContext): String {
    val subtitle = authContext.subtitle
    return if (subtitle.isNullOrEmpty()) authContext.title else "${authContext.title}\n$subtitle"
}

/**
 * Maps a gated-sign failure to the closed error set. A dismissed prompt is
 * `userCanceled`; a failed authentication (indistinguishably a re-enrollment
 * invalidation on Apple) is `authFailed`; an unpresentable prompt is
 * `authContextRequired`. LocalAuthentication and OSStatus codes both map; every
 * other code is `hardwareError`.
 */
internal fun mapGatedSignFailure(error: NSError?): SignetErrorCode {
    if (error == null) return SignetErrorCode.hardwareError
    val code: Long = error.code.convert()
    if (error.domain == LAErrorDomain) {
        return when (code) {
            LAErrorUserCancel, LAErrorAppCancel, LAErrorSystemCancel -> SignetErrorCode.userCanceled
            LAErrorAuthenticationFailed, LAErrorBiometryLockout -> SignetErrorCode.authFailed
            LAErrorNotInteractive, LAErrorInvalidContext, LAErrorPasscodeNotSet,
            LAErrorBiometryNotAvailable, LAErrorBiometryNotEnrolled -> SignetErrorCode.authContextRequired
            else -> SignetErrorCode.hardwareError
        }
    }
    return when (code) {
        errSecUserCanceled.convert<Long>() -> SignetErrorCode.userCanceled
        errSecAuthFailed.convert<Long>() -> SignetErrorCode.authFailed
        errSecInteractionNotAllowed.convert<Long>() -> SignetErrorCode.authContextRequired
        else -> SignetErrorCode.hardwareError
    }
}

/** Serializes auth-gated signing: a second gated sign while a prompt is outstanding is rejected. */
internal class SignGate {
    private val busy = AtomicInt(0)

    fun tryEnter(): Boolean = busy.compareAndSet(0, 1)

    fun exit() {
        busy.value = 0
    }
}
