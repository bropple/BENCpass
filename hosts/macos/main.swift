// BENCpass native host for macOS: Touch ID in front of one random string.
//
// See ../PROTOCOL.md for the messages. In short: the browser hands this program
// 32 bytes it cannot interpret, it puts them in the Keychain behind a biometric
// access control, and hands them back when Touch ID says so. It never sees the
// master password, the vault key, or a record.
//
// Build with ../build-macos.sh, which also installs the manifest.

import Foundation
import LocalAuthentication
import Security

let SERVICE = "net.ropple.bencpass.auth"
let VERSION = "1.0.0"
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

// ---- the keychain -----------------------------------------------------------
//
// The file-based keychain, deliberately, rather than the data-protection one.
// The data-protection keychain on macOS requires the caller to be signed with a
// `keychain-access-groups` entitlement backed by a real team identifier, which
// a locally built command-line tool does not have — it fails with
// errSecMissingEntitlement (-34018) and there is no way around that short of a
// paid developer account. The file-based keychain honours the same
// `SecAccessControl`, and `.biometryCurrentSet` means the item is destroyed if
// the enrolled fingerprints change, which is the property that matters.

func query(_ id: String) -> [String: Any] {
    [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: SERVICE,
        kSecAttrAccount as String: id,
    ]
}

func store(id: String, secret: Data) -> [String: Any] {
    guard biometricsAvailable() else { return fail("unavailable") }

    var accessError: Unmanaged<CFError>?
    guard
        let access = SecAccessControlCreateWithFlags(
            nil,
            // ThisDeviceOnly: never in a Keychain backup, never on another Mac.
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            .biometryCurrentSet,
            &accessError
        )
    else {
        return fail("error", "SecAccessControlCreateWithFlags failed")
    }

    // Replace rather than update: the access control is set at creation, so an
    // update cannot be trusted to reapply it.
    SecItemDelete(query(id) as CFDictionary)

    var add = query(id)
    add[kSecValueData as String] = secret
    add[kSecAttrAccessControl as String] = access
    add[kSecAttrLabel as String] = "BENCpass device secret"

    let status = SecItemAdd(add as CFDictionary, nil)
    guard status == errSecSuccess else {
        return fail("error", "SecItemAdd: \(status)")
    }
    return ["ok": true]
}

func retrieve(id: String, prompt: String) -> [String: Any] {
    switch authenticate(prompt) {
    case .failure(let reason):
        return fail(reason.rawValue)
    case .success(let context):
        var get = query(id)
        get[kSecReturnData as String] = true
        get[kSecMatchLimit as String] = kSecMatchLimitOne
        // Already authenticated, so this does not prompt again.
        get[kSecUseAuthenticationContext as String] = context

        var item: CFTypeRef?
        let status = SecItemCopyMatching(get as CFDictionary, &item)
        if status == errSecItemNotFound { return fail("not-found") }
        guard status == errSecSuccess, let data = item as? Data else {
            // errSecUserCanceled can still surface here if the context expired
            // between the prompt and the read.
            if status == errSecUserCanceled { return fail("cancelled") }
            return fail("error", "SecItemCopyMatching: \(status)")
        }
        return ["ok": true, "secret": data.base64EncodedString()]
    }
}

func forget(id: String) -> [String: Any] {
    let status = SecItemDelete(query(id) as CFDictionary)
    // Deleting something that was never there is a success. The caller wants it
    // gone, and it is gone.
    guard status == errSecSuccess || status == errSecItemNotFound else {
        return fail("error", "SecItemDelete: \(status)")
    }
    return ["ok": true]
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

    default:
        return fail("unsupported", "unknown op")
    }
}

// One message, one reply, then out. A host that lingers holds up the browser.
if let message = readMessage() {
    writeMessage(handle(message))
}
