# The BENCpass native host protocol

One small program per machine, whose only job is to hold a random string
somewhere the operating system will only open for a fingerprint.

It is deliberately the least interesting component in the system. It never sees
the master password, the vault key, or a single record. It is handed 32 random
bytes it cannot interpret, and asked for them back later. If it is compromised,
what leaks is a string that is useless without the vault file it wraps — and if
it is absent, BENCpass works exactly as it did before, asking for the master
password.

Everything cryptographic happens in `src/core/`. See the second-wrapping section
of `src/core/vault.js` for what the secret actually unlocks.

## Transport

Firefox [native messaging]: the browser starts the program, writes one message
to its stdin and reads one from its stdout, then lets it exit. Each message is a
little-endian `uint32` byte count followed by that many bytes of UTF-8 JSON.

[native messaging]: https://developer.mozilla.org/docs/Mozilla/Add-ons/WebExtensions/Native_messaging

The host is registered by a manifest named `net.ropple.bencpass.auth.json`:

```json
{
  "name": "net.ropple.bencpass.auth",
  "description": "BENCpass biometric unlock",
  "path": "/absolute/path/to/the/binary",
  "type": "stdio",
  "allowed_extensions": ["bencpass@ropple.net"]
}
```

| | |
|---|---|
| macOS | `~/Library/Application Support/Mozilla/NativeMessagingHosts/` |
| Linux | `~/.mozilla/native-messaging-hosts/` |
| Windows | `HKCU\Software\Mozilla\NativeMessagingHosts\net.ropple.bencpass.auth`, whose default value is the full path to the manifest file |

Zen reads the same locations as Firefox.

`allowed_extensions` is the access control. Only the listed add-on can start
this program, so no web page and no other extension can reach the keystore
through it.

## Messages

Every request carries `v` (the protocol version, currently `1`) and `op`. Every
reply carries `ok`. A failure carries `reason`, from the fixed set below, and
may carry `detail` for a human.

### `hello`

```json
→ {"v":1,"op":"hello"}
← {"ok":true,"platform":"macos","biometrics":"touchid","version":"1.0.0"}
```

`biometrics` is what this machine can do **right now** — `touchid`, `hello`, or
`none`. A Mac whose Touch ID is switched off and a PC with no Hello enrolment
both answer `none`, and the extension will then not offer to enrol. This
distinction matters: an enrolment that cannot be satisfied later would be a
second way into the vault guarded by nothing.

### `store`

```json
→ {"v":1,"op":"store","id":"<opaque>","secret":"<base64 of 32 bytes>"}
← {"ok":true}
```

Overwrites any secret already held under that id. The host must place it behind
the platform's biometric gate — see the per-platform notes — and must not write
it anywhere else, including a log.

### `get`

```json
→ {"v":1,"op":"get","id":"<opaque>","prompt":"Unlock BENCpass"}
← {"ok":true,"secret":"<base64>"}
← {"ok":false,"reason":"cancelled"}
```

The call that raises the prompt. It may take as long as the person takes; the
extension does not time it out. `prompt` is the sentence to show and is under
BENCpass's control rather than the host's, so the wording stays consistent with
the rest of the interface.

### `forget`

```json
→ {"v":1,"op":"forget","id":"<opaque>"}
← {"ok":true}
```

Removing a secret that was never there is a success, not a failure.

## Failure reasons

| `reason` | Means |
|---|---|
| `cancelled` | the person dismissed the prompt, or failed to authenticate |
| `unavailable` | no biometric hardware, or nothing enrolled with the OS |
| `not-found` | no secret is held under that id |
| `unsupported` | the `op` or the `v` is not one this host implements |
| `error` | anything else; `detail` says what |

The extension adds two of its own that no host ever sends: `no-host` when there
is nothing installed to talk to, and `bad-reply` when what came back was not
JSON of the right shape.

## Rules for a host

1. **One reply per request, then exit.** A host that hangs holds up the browser.
2. **Never write the secret anywhere but the keystore.** Not to a log, not to a
   temporary file, not to stderr. Firefox captures stderr into the browser
   console.
3. **Never prompt on `store` or `forget`.** Only `get` costs a fingerprint.
   Enrolment already proved the master password; asking twice teaches people to
   approve prompts without reading them.
4. **Fail closed.** If the keystore cannot be reached, answer `unavailable`
   rather than falling back to storing the secret unprotected. A vault that
   asks for a password is working correctly; one whose second key is lying on
   the disk in the clear is not.

## What each platform can actually enforce

Measured, not assumed. The distinction that matters is not "does this system
have a fingerprint reader" but "will something refuse to release a key without
one" — a service that answers yes or no can be skipped by anything that wanted
the secret in the first place.

| | Trusted path | State |
|---|---|---|
| macOS, Secure Enclave | yes | built and tested; blocked on an Apple provisioning profile, which needs a paid account and annual renewal — `hosts/macos/README.md` |
| Windows Hello, TPM | yes | not built. Gated on package identity, which unlike Apple's entitlement is something you can grant yourself with a self-signed sparse package |
| Linux, fprintd | **no** | answers a question rather than withholding a key. Not worth building |
| Linux, TPM 2.0 | no biometric input | can seal to a PIN, which is a password by another name |
| **FIDO2 with user verification** | **yes** | not built, and the most promising thing here: one implementation, hardware-backed on all three platforms, no Apple paperwork. Needs a token rather than a built-in reader |
| WebAuthn PRF, no host at all | yes | blocked on Firefox. Shipped in Chromium and Safari 18; Firefox 150 solved the extension-origin half but not the PRF half. When it lands, most of this table stops mattering |
