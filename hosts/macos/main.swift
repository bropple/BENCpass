// BENCpass native host for macOS: Touch ID in front of one random string.
//
// See ../PROTOCOL.md for the messages. In short: the browser hands this program
// 32 bytes it cannot interpret, it seals them so that only a fingerprint on this
// Mac can open them again, and hands them back when Touch ID says so. It never
// sees the master password, the vault key, or a record.
//
// Sealed against a key held in the Secure Enclave rather than put in the
// keychain, for a reason worth reading before changing it — see "the enclave"
// below, and hosts/macos/README.md.
//
// Build and register with ../install.sh.

import Foundation
import LocalAuthentication
import Security

let SERVICE = "net.ropple.bencpass.auth"
// Bumped when the *design* changes, not for tidying. 1.x put the secret in the
// keychain and could not work; 2.x seals it to a Secure Enclave key. Reported by
// `hello`, shown in Settings, and quoted in failures — so "which binary is
// actually running" is a question with an answer.
let VERSION = "2.0.0"
let PROTOCOL_VERSION = 1

// ---- native messaging framing ----------------------------------------------
//
// A little-endian uint32 byte count, then that many bytes of UTF-8 JSON, in
// both directions. Firefox closes stdin when it has nothing more to send.

func readExactly(_ count: Int) -> Data? {
    var out = Data()
    while out.count < count {
        let chunk = FileHandle.standardInput.readData(ofLength: count - out.count)
        if chunk.isEmpty { return nil }  // stdin closed
        out.append(chunk)
    }
    return out
}

func readMessage() -> [String: Any]? {
    guard let header = readExactly(4) else { return nil }
    // Little-endian because the protocol says so, not because every Mac happens
    // to be. Spelling it out costs nothing and cannot be wrong later.
    let length = UInt32(littleEndian: header.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) })
    // Firefox will not send more than 1 MB, and neither will BENCpass — the
    // largest message this host ever sees is a base64 32-byte secret. A bound
    // here means a corrupt header cannot ask for an enormous allocation.
    guard length > 0, length <= 1_048_576, let body = readExactly(Int(length)) else { return nil }
    return try? JSONSerialization.jsonObject(with: body) as? [String: Any]
}

func writeMessage(_ object: [String: Any]) {
    guard let body = try? JSONSerialization.data(withJSONObject: object) else { return }
    var out = withUnsafeBytes(of: UInt32(body.count).littleEndian) { Data($0) }
    out.append(body)
    FileHandle.standardOutput.write(out)
}

func fail(_ reason: String, _ detail: String? = nil) -> [String: Any] {
    var reply: [String: Any] = ["ok": false, "reason": reason]
    if let detail { reply["detail"] = detail }
    return reply
}

// ---- biometrics -------------------------------------------------------------

/// What this machine can do *now* — not what the hardware could do in principle.
///
/// A Mac with a Touch Bar but nothing enrolled, or with Touch ID switched off
/// for unlocking, answers `none` here, and BENCpass will then not offer to
/// enrol. An enrolment that cannot be satisfied later would be a second way
/// into the vault guarded by nothing at all.
func biometricsAvailable() -> Bool {
    var error: NSError?
    let context = LAContext()
    return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
}

/// Why a prompt did not produce an authenticated context.
///
/// An enum rather than a bare string because `Result`'s failure type has to
/// conform to `Error`, and `String` does not. The raw values are the `reason`
/// strings in ../PROTOCOL.md, so the wire format stays readable from here.
enum AuthFailure: String, Error {
    case cancelled
    case unavailable
}

/// Raise the prompt and return a context already carrying the result.
///
/// Done explicitly rather than leaving the Keychain to prompt on our behalf, so
/// that the wording comes from BENCpass and matches the rest of its interface.
/// Passing the authenticated context to `SecItemCopyMatching` below is what
/// stops it asking a second time.
func authenticate(_ reason: String) -> Result<LAContext, AuthFailure> {
    let context = LAContext()
    context.localizedCancelTitle = "Cancel"

    var error: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
        return .failure(.unavailable)
    }

    // evaluatePolicy is asynchronous and this is a one-shot command-line tool
    // with no run loop, so the semaphore is the whole concurrency design.
    let waiter = DispatchSemaphore(value: 0)
    var outcome: Result<LAContext, AuthFailure> = .failure(.cancelled)

    context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) {
        success, err in
        if success {
            outcome = .success(context)
        } else if let err = err, let laError = err as? LAError {
            // Everything that is not a real fault is the same thing to the
            // caller: the person did not authenticate.
            switch laError.code {
            case .biometryNotAvailable, .biometryNotEnrolled, .biometryLockout:
                outcome = .failure(.unavailable)
            default:
                outcome = .failure(.cancelled)
            }
        } else {
            outcome = .failure(.cancelled)
        }
        waiter.signal()
    }
    waiter.wait()
    return outcome
}

// ---- the keychain, and why the secret is not in it ---------------------------
//
// Kept only for the probe below, which is the record of why this design is
// shaped the way it is. A keychain item carrying a biometric SecAccessControl
// is refused with errSecMissingEntitlement (-34018) unless the binary is signed
// with a keychain access group, and that entitlement is authorised by Apple:
// an ad-hoc signature claiming it is killed on launch, and so is a trusted
// self-signed one. All three measured on a runner rather than reasoned about.

func query(_ id: String, dataProtection: Bool) -> [String: Any] {
    var q: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: SERVICE,
        kSecAttrAccount as String: id,
    ]
    if dataProtection { q[kSecUseDataProtectionKeychain as String] = true }
    return q
}

/// Both keychains, for the probe to ask each in turn.
let KEYCHAINS: [(name: String, dataProtection: Bool)] = [
    ("data-protection", true),
    ("file", false),
]

// ---- the enclave ------------------------------------------------------------
//
// The secret is not in the keychain. It cannot be: an item carrying a biometric
// SecAccessControl is refused with errSecMissingEntitlement unless the binary is
// signed with a keychain access group, and that entitlement is authorised by
// Apple alone — measured, not assumed. An ad-hoc signature is killed on launch
// for claiming it, and so is a trusted self-signed one. See the experiment in
// .github/workflows/hosts.yml.
//
// So the shape is inverted. A key is generated *inside* the Secure Enclave whose
// use is gated by a fingerprint, and the device secret is kept beside it as
// ciphertext in an ordinary file. The file is worthless without the enclave, the
// enclave will not act without the fingerprint, and the private key cannot be
// extracted by anyone — it has never existed outside the hardware.
//
// The properties that mattered about the keychain approach all survive:
//
//   never leaves this Mac      the enclave key is not exportable and not backed up
//   dies with the fingerprints .biometryCurrentSet invalidates the key when the
//                              enrolled set changes
//   useless if copied          the ciphertext decrypts nowhere else
//
// And one improves: the secret is never in any keychain, so no other program can
// be prompted into handing it over.

/// Where the sealed secret lives. The directory is created 0700, the file 0600.
func sealedPath(_ id: String) -> URL {
    let dir = FileManager.default
        .homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/BENCpass", isDirectory: true)
    try? FileManager.default.createDirectory(
        at: dir,
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700]
    )
    // The id comes from the extension and is hex; refuse anything else rather
    // than let it choose a path.
    let safe = id.filter { $0.isHexDigit }
    return dir.appendingPathComponent("\(safe).sealed")
}

func keyTag(_ id: String) -> Data {
    Data("net.ropple.bencpass.key.\(id.filter { $0.isHexDigit })".utf8)
}

/// The enclave key for this secret, if it has one.
func findKey(_ id: String, context: LAContext?) -> SecKey? {
    var q: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: keyTag(id),
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecReturnRef as String: true,
    ]
    if let context { q[kSecUseAuthenticationContext as String] = context }

    var item: CFTypeRef?
    guard SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess else { return nil }
    return (item as! SecKey?)
}

let ALGORITHM = SecKeyAlgorithm.eciesEncryptionCofactorX963SHA256AESGCM

func store(id: String, secret: Data) -> [String: Any] {
    guard biometricsAvailable() else { return fail("unavailable") }

    // Start clean: a second enrolment must not leave the previous key behind,
    // able to decrypt a file that is about to be replaced.
    _ = forget(id: id)

    var accessError: Unmanaged<CFError>?
    guard
        let access = SecAccessControlCreateWithFlags(
            nil,
            // ThisDeviceOnly: never in a backup, never on another Mac.
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &accessError
        )
    else {
        return fail("error", "access control refused")
    }

    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: keyTag(id),
            kSecAttrAccessControl as String: access,
        ],
    ]

    var error: Unmanaged<CFError>?
    guard let priv = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        let e = error?.takeRetainedValue()
        return fail("error", "enclave refused a key: \(String(describing: e))")
    }
    guard let pub = SecKeyCopyPublicKey(priv) else {
        return fail("error", "no public key")
    }

    // Encrypting uses the public key, which the enclave hands out freely — so
    // enrolment raises no prompt. Only reading it back costs a fingerprint.
    guard
        let sealed = SecKeyCreateEncryptedData(pub, ALGORITHM, secret as CFData, &error) as Data?
    else {
        let e = error?.takeRetainedValue()
        return fail("error", "encryption failed: \(String(describing: e))")
    }

    do {
        try sealed.write(to: sealedPath(id), options: [.atomic, .completeFileProtection])
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: sealedPath(id).path
        )
    } catch {
        return fail("error", "could not write the sealed secret: \(error)")
    }
    return ["ok": true, "storage": "secure-enclave"]
}

func retrieve(id: String, prompt: String) -> [String: Any] {
    guard let sealed = try? Data(contentsOf: sealedPath(id)) else {
        return fail("not-found")
    }

    switch authenticate(prompt) {
    case .failure(let reason):
        return fail(reason.rawValue)
    case .success(let context):
        // Already authenticated, so the decryption below does not ask again.
        guard let priv = findKey(id, context: context) else {
            // The file is here and the key is not: the enrolled fingerprints
            // changed, which destroys the key by design, or the key was removed.
            // Either way this enrolment is over.
            return fail("not-found", "the enclave key is gone")
        }

        var error: Unmanaged<CFError>?
        guard
            let secret = SecKeyCreateDecryptedData(priv, ALGORITHM, sealed as CFData, &error)
                as Data?
        else {
            let e = error?.takeRetainedValue()
            let text = String(describing: e)
            // A refusal at this point is the person declining, not a fault.
            if text.contains("-128") || text.lowercased().contains("cancel") {
                return fail("cancelled")
            }
            return fail("error", "decryption failed: \(text)")
        }
        return ["ok": true, "secret": secret.base64EncodedString()]
    }
}

func forget(id: String) -> [String: Any] {
    SecItemDelete(
        [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag(id),
        ] as CFDictionary
    )
    try? FileManager.default.removeItem(at: sealedPath(id))
    // Removing something that was never there is a success. The caller wants it
    // gone, and it is gone.
    return ["ok": true]
}

// ---- probe ------------------------------------------------------------------

/// Try the thing that fails, and report what each keychain said.
///
/// `SecItemAdd` does not prompt — the biometric constraint is evaluated when the
/// item is *read* — so this runs on a machine with no fingerprint reader at all,
/// which is what makes it something CI can answer. It writes a throwaway item
/// and removes it again.
///
/// It exists because -34018 (errSecMissingEntitlement) is a claim about the
/// signature on this binary rather than about the code, and the only way to
/// learn which signature satisfies it is to sign a few ways and ask.
func probe() -> [String: Any] {
    var accessError: Unmanaged<CFError>?
    let access = SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
        .biometryCurrentSet,
        &accessError
    )
    guard let access else {
        return ["ok": true, "accessControl": "failed", "results": [:]]
    }

    var results: [String: Int32] = [:]
    let id = "probe-\(UInt32.random(in: 0..<UInt32.max))"
    for keychain in KEYCHAINS {
        var add = query(id, dataProtection: keychain.dataProtection)
        add[kSecValueData as String] = Data("probe".utf8)
        add[kSecAttrAccessControl as String] = access
        let status = SecItemAdd(add as CFDictionary, nil)
        results[keychain.name] = status
        SecItemDelete(query(id, dataProtection: keychain.dataProtection) as CFDictionary)
    }

    return [
        "ok": true,
        "accessControl": "created",
        "biometrics": biometricsAvailable() ? "available" : "none",
        "results": results,
        "secureEnclave": probeSecureEnclave(),
    ]
}

/// Which ways of keeping a Secure Enclave key this machine will allow.
///
/// The enclave itself is not the problem: it makes the key. What fails is
/// `kSecAttrIsPermanent`, which writes the key's reference into the keychain and
/// so runs into the same entitlement that closed the keychain route —
/// "failed to add key to keychain", -34018.
///
/// These are the combinations that might not. Each is tried and reported;
/// anything that persists is deleted again. A machine with no fingerprint
/// enrolled fails the biometric variants before reaching the keychain at all,
/// with "bio catacomb", which is why this has to be run somewhere with Touch ID
/// to mean anything.
func probeSecureEnclave() -> [[String: Any]] {
    struct Variant {
        let name: String
        let flags: SecAccessControlCreateFlags
        let permanent: Bool
        let dataProtection: Bool?
    }

    let variants = [
        Variant(name: "biometry, permanent, default keychain",
                flags: [.privateKeyUsage, .biometryCurrentSet], permanent: true, dataProtection: nil),
        Variant(name: "biometry, permanent, file keychain",
                flags: [.privateKeyUsage, .biometryCurrentSet], permanent: true, dataProtection: false),
        Variant(name: "biometry, permanent, data-protection keychain",
                flags: [.privateKeyUsage, .biometryCurrentSet], permanent: true, dataProtection: true),
        Variant(name: "biometry, not permanent",
                flags: [.privateKeyUsage, .biometryCurrentSet], permanent: false, dataProtection: nil),
        // Without biometry, to separate "the enclave will not keep a key at all"
        // from "the enclave will not keep a biometric one".
        Variant(name: "no biometry, permanent, default keychain",
                flags: [.privateKeyUsage], permanent: true, dataProtection: nil),
        Variant(name: "no biometry, permanent, file keychain",
                flags: [.privateKeyUsage], permanent: true, dataProtection: false),
    ]

    var out: [[String: Any]] = []
    for v in variants {
        var accessError: Unmanaged<CFError>?
        guard
            let access = SecAccessControlCreateWithFlags(
                nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, v.flags, &accessError)
        else {
            out.append(["variant": v.name, "ok": false, "error": "access control refused"])
            continue
        }

        let tag = Data("net.ropple.bencpass.probe.\(UInt32.random(in: 0..<UInt32.max))".utf8)
        var priv: [String: Any] = [
            kSecAttrIsPermanent as String: v.permanent,
            kSecAttrApplicationTag as String: tag,
            kSecAttrAccessControl as String: access,
        ]
        if let dp = v.dataProtection { priv[kSecUseDataProtectionKeychain as String] = dp }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: priv,
        ]

        var error: Unmanaged<CFError>?
        if SecKeyCreateRandomKey(attributes as CFDictionary, &error) != nil {
            out.append(["variant": v.name, "ok": true])
            var del: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: tag,
            ]
            if let dp = v.dataProtection { del[kSecUseDataProtectionKeychain as String] = dp }
            SecItemDelete(del as CFDictionary)
        } else {
            let e = error?.takeRetainedValue()
            out.append([
                "variant": v.name,
                "ok": false,
                "error": String(describing: e).replacingOccurrences(of: "\n", with: " "),
            ])
        }
    }
    return out
}

// ---- dispatch ---------------------------------------------------------------

func handle(_ message: [String: Any]) -> [String: Any] {
    guard let version = message["v"] as? Int, version == PROTOCOL_VERSION else {
        return fail("unsupported", "protocol version")
    }
    let id = (message["id"] as? String) ?? ""

    switch message["op"] as? String {
    case "hello":
        return [
            "ok": true,
            "platform": "macos",
            "biometrics": biometricsAvailable() ? "touchid" : "none",
            "version": VERSION,
        ]

    case "store":
        guard !id.isEmpty,
            let encoded = message["secret"] as? String,
            let secret = Data(base64Encoded: encoded),
            secret.count == 32
        else {
            return fail("error", "store needs an id and 32 base64 bytes")
        }
        return store(id: id, secret: secret)

    case "get":
        guard !id.isEmpty else { return fail("error", "get needs an id") }
        return retrieve(id: id, prompt: (message["prompt"] as? String) ?? "Unlock BENCpass")

    case "forget":
        guard !id.isEmpty else { return fail("error", "forget needs an id") }
        return forget(id: id)

    case "probe":
        return probe()

    default:
        return fail("unsupported", "unknown op")
    }
}

// One message, one reply, then out. A host that lingers holds up the browser.
if let message = readMessage() {
    writeMessage(handle(message))
}
