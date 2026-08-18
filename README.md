<img src="assets/brand/BENCO_Logo_README.png" alt="BENCO" align="right" width="120">

# BENCpass

[![CI](https://github.com/bropple/BENCpass/actions/workflows/ci.yml/badge.svg)](https://github.com/bropple/BENCpass/actions/workflows/ci.yml)
[![Security](https://github.com/bropple/BENCpass/actions/workflows/security.yml/badge.svg)](https://github.com/bropple/BENCpass/actions/workflows/security.yml)
[![CodeQL](https://github.com/bropple/BENCpass/actions/workflows/codeql.yml/badge.svg)](https://github.com/bropple/BENCpass/actions/workflows/codeql.yml)
[![Server image](https://github.com/bropple/BENCpass/actions/workflows/server-image.yml/badge.svg)](https://github.com/bropple/BENCpass/actions/workflows/server-image.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A self-hosted, end-to-end encrypted password manager for Firefox and Zen, meant
to replace the browser's built-in one. Your vault syncs between your own
machines through a small server you run yourself — on a NAS, a spare box, or
anything else that stays on.

The server stores ciphertext and holds no key. It cannot read a record, and
because it cannot read one, it cannot merge either — all merging happens on the
clients.

**You do not need the server.** With none configured, nothing is sent anywhere
and everything below still works; what you give up is having the same vault on
a second machine. If you run that way, use the export — the vault then lives in
one browser profile, and a profile is not a thing anyone backs up on purpose.

> **Not finished.** Everything below the line works and is tested. Still
> missing: the recovery kit. Until one exists, forgetting the master password
> loses the vault with no way back, and no amount of self-hosting changes that
> — so keep a recent export somewhere safe.

| | |
|---|---|
| ✅ Crypto core — Argon2id, per-record AES-256-GCM | `src/core/crypto.js` |
| ✅ Vault — records, history, timestamps, tombstones | `src/core/vault.js` |
| ✅ Causal merge with conflict preservation | `src/core/merge.js` |
| ✅ Manager UI | `src/ui/` |
| ✅ Sync server + client | `server/`, `src/core/sync.js` |
| ✅ Extension: manifest, background, content script, popup, overlay | `src/ext/` |
| ✅ Origin matching against the Public Suffix List | `src/core/match.js` |
| ✅ Form-field classification, logins and addresses | `src/core/fields.js` |
| ✅ Address model: every WHATWG token, country and state dropdowns | `src/core/address.js` |
| ✅ Biometric unlock — Touch ID, Hello or a security key, via WebAuthn PRF | `src/ext/webauthn.js` |
| ✅ Import and export — BENCpass JSON, Firefox, Chrome, Bitwarden, KeePass | `src/core/transfer.js` |
| ⬜ Recovery kit | — |

Reviewing this, or just want the short version of how it holds together?
[`REVIEWERS.md`](REVIEWERS.md) answers the questions the source raises — what
leaves the machine, why each permission is asked for, and how to reproduce every
generated file in the package.

## What leaves your machine

Nothing, unless you set up a server — and then only ciphertext, to the address
you typed in.

The manifest says so in the form Firefox checks:

```json
"data_collection_permissions": {
  "required": ["none"],
  "optional": ["authenticationInfo", "personallyIdentifyingInfo"]
}
```

**Required is `none`** because BENCpass works completely with no server
configured, and in that state it makes no network request at all.

**Optional names what sync sends** when you do configure one:
`authenticationInfo` for the passwords, `personallyIdentifyingInfo` for the
names, addresses, phone numbers and email in address records, and
`browsingActivity` for the site addresses saved against each login — a list of
the sites you hold accounts on is what that category describes, even though it
is nobody's browsing history.

Both are declared even though the server only ever receives ciphertext and holds
no key. Mozilla's rule is about the boundary, not the destination or the
encryption — *"any data collected, used, transferred, shared, or handled outside
the add-on or the local browser"* — and a server you run yourself is still
outside the browser. Declaring less because it is encrypted, or because the
server is yours, would be reading the rule for what it lets us say rather than
for what it asks.

The server learns what any storage host learns: how many records exist and when
each one changes. That is stated in ARCHITECTURE.md §3 rather than left to be
discovered.

## Layout

```
src/core/     crypto, vault, merge, sync — no browser APIs, tested under Node
src/ui/       the manager page
src/vendor/   Argon2 (hash-wasm), vendored as one ES module
server/       the Go sync server
tools/        preview harness, icon and build scripts
hosts/        a native host, built and then abandoned — see the note below
test/         Node tests, including integration tests against the real server
build/        everything generated — gitignored whole, safe to delete
```

Nothing is written outside `build/` except the screenshots and the test browser
profile, which are kept where they are because they are looked at and lived in
rather than built. One ignored directory rather than a list of rules that has
to be kept in step with the scripts: a generated file landing beside its source
is how a working tree ends up dirty for reasons nobody can account for, and how
a stray page ends up inside a packaged extension.

## Running things

```sh
npm install && npm test     # the sync ones build and run the Go server
cd server && go test ./...  # unit and API tests, plus -race

tools/selftest.sh           # drive the extension in a real browser, unattended
tools/run-extension.sh      # load into a test profile, open the form-shapes page
tools/run-extension.sh fresh   # ...discarding the previous test vault
tools/run-extension.sh verbose # ...logging what the browser itself prints
tools\run-extension.ps1     # the same on Windows; -Fresh to discard
npx web-ext lint --source-dir=src --self-hosted
npx web-ext build --source-dir=src --artifacts-dir=build/ext

tools/preview.sh            # the manager UI, with a throwaway seeded vault
tools/preview.sh shot       # screenshots of every state, into screenshots/
cd server && go run . -dir ./data   # prints a bootstrap enrolment code
node tools/gen-countries.mjs --check # the country table still matches ICU
```

`npm test` skips the integration tests if no Go toolchain is present, and says
so rather than passing quietly.

### Keyboard

| | |
|---|---|
| `Alt+Shift+B` | open the BENCpass sidebar |
| `Ctrl+Shift+L` | offer a login for the page |

Rebind them at `about:addons` → gear → Manage Extension Shortcuts.

The sidebar shortcut exists because nothing else can open a sidebar from a web
page. `sidebarAction.open()` is not exposed to an extension page framed inside
one, and from the background it refuses with *"may only be called from a user
input handler"*. A keyboard command **is** a user input handler, and Firefox
reserves the command name `_execute_sidebar_action` to open the sidebar itself —
so there is no API call left to refuse.

The test browser uses a dedicated profile at `.bencpass-profile/`, kept between
runs so the vault survives — recreating it every launch makes autofill
essentially untestable.

### "Restart to update"

Updates are turned off in the test profile, from `tools/test-prefs.txt` — one
list, read by `run-extension.sh`, `run-extension.ps1` and `selftest.sh` alike.
A second instance would otherwise stage an update into the shared installation,
and the browser you actually use notices its own files changing underneath it.

The prefs do not behave the same on every platform, which is why a list that
looked settled on Windows still produced the nag on macOS:

| | |
|---|---|
| `app.update.auto` | per-**profile** on macOS and Linux; per-**installation** on Windows, read from `update-config.json`, where setting the pref does nothing |
| `app.update.service.enabled` | the Windows Maintenance Service. There is no such service on macOS |
| `app.update.promptWaitTime` | the one that actually silences the nag — the restart prompt is scheduled 68 years out instead of the default twelve hours |

Every name in that file was checked against the browser's own `omni.ja` rather
than against memory. Three the list used to carry are not read by any current
build: `app.update.enabled`, `app.update.checkInstallTime`, and
`app.update.background.scheduling.enabled` — whose real name is
`app.update.background.enabled`.

**There is no supported pref that turns update checking off outright.**
`app.update.disabledForTesting` exists but is gated on `Cu.isInAutomation ||
Marionette.running || RemoteAgent.running`, none of which `web-ext` turns on.
The only complete switch is the enterprise policy, and it belongs to the
installation rather than to a profile — so it stops your ordinary browsing
updating too, and it is not something these scripts will do to your machine
behind your back. If you want it anyway, on macOS:

```sh
mkdir -p "/Applications/Zen.app/Contents/Resources/distribution"
echo '{"policies":{"DisableAppUpdate":true}}' \
  > "/Applications/Zen.app/Contents/Resources/distribution/policies.json"
```

Remember you have done it; the browser will then never update itself again.

### The self-test

`tools/selftest.sh` starts a headless browser with the extension loaded and
lets the test page drive it — page script and the content script share a DOM, so
an event dispatched by one reaches the other's listeners. The page reports what
it found back to the local server, and the script prints a pass/fail table.

It covers what has actually regressed: which fields get an anchor, what those
anchors look like, whether the menu opens and stays open, whether anchors
survive the page being scrolled, and that nothing is ever filled — or chosen in
a dropdown — without a person asking for it. The vault stays locked throughout,
since nothing can type a master password into the manager.

### `npm install` reports high-severity vulnerabilities

Expected, and not worth acting on. All of them trace to one package:

```
web-ext (devDependency) -> addons-linter -> image-size
    "ICNS parser allows denial of service through an infinite loop"
```

`web-ext` is the lint-and-run tool. It is not shipped: the built `.xpi` contains
no `node_modules` at all, and the only runtime dependency is `hash-wasm`. The
bug needs `web-ext lint` pointed at a hostile macOS icon file; the icons here
are PNGs this repository generates.

**Do not run `npm audit fix --force`.** It will move `web-ext` across a major
version to fix a denial of service in a code path that never runs, and break the
tooling in exchange.

**On macOS.** The shell scripts work as they are. Zen and Firefox live inside
`.app` bundles rather than on `PATH`, so `tools/find-browser.sh` looks in
`/Applications` and `~/Applications` as well; set `BROWSER_BIN` if it guesses
wrong:

```sh
BROWSER_BIN='/Applications/Zen Browser.app/Contents/MacOS/zen' tools/run-extension.sh
```

Every run now prints the binary it chose, on the `browser:` line, so a bad guess
shows up before the browser does.

### `connect ECONNREFUSED 127.0.0.1:<port>`

Not the test server. That is `web-ext` giving up on the browser: it launches it
with `-start-debugger-server <port>`, dials that port for thirty seconds, and
says this when nothing ever answers.

The script now explains it rather than leaving you with that line. It always
runs `web-ext` verbose into `$TMPDIR/bencpass-web-ext.log`, because the
browser's own stdout and stderr only reach `web-ext`'s output at debug level —
and they are the only place that says which of four things happened.
`DevToolsStartup.sys.mjs` prints a distinct line for three of them:

| What the log says | What it means |
|---|---|
| `Started devtools server on <port>` | it worked; something on loopback is in the way |
| `Could not run chrome debugger! You need...` | `devtools.chrome.enabled` and `devtools.debugger.remote-enabled` were not both true |
| `Unable to start devtools server on <port>: ...` | the socket would not open — something has the port |
| *nothing* | the flag was never read: the browser exited during startup, handed off to an instance already running, or has devtools disabled by policy |

Both of those prefs ship `sticky` and default to **false**, so a profile that
has ever had them off keeps them off. `web-ext` sets both, and
`tools/test-prefs.txt` sets `devtools.chrome.enabled` again for good measure —
but not `devtools.debugger.remote-enabled`, which `web-ext` lists in
`nonOverridablePreferences` and will throw a `UsageError` over if `--pref`
names it.

The last row is the intermittent one, and on a desktop it is almost always a
browser instance that is still running. The script warns before launching if
anything already holds the test profile. `tools/run-extension.sh verbose` shows
the whole log on screen instead of a summary; `fresh` rules out the profile.

**On Windows.** The extension itself is the same `.xpi` — it is browser
JavaScript and contains no platform-specific code — and the Go server
cross-compiles to a static `.exe`. Only the developer tooling differs, and only
`run-extension` has a Windows counterpart so far; the rest of `tools/` is POSIX
shell and wants Git Bash or WSL.

Node 22 or later is required (`engines` in `package.json` enforces it). On a
fresh Windows machine:

```
winget install OpenJS.NodeJS.LTS
```

The `.LTS` suffix matters — plain `OpenJS.NodeJS` tracks the Current line, which
moves fast for no benefit here. **Open a new terminal afterwards**: winget
updates PATH but the shell you ran it from will not see the change, which looks
exactly like the install having failed.

Then:

```
.\tools\run-extension.ps1
.\tools\run-extension.ps1 -Browser "C:\Path\To\zen.exe"
```

On a default `RemoteSigned` policy that is all it takes, provided the files were
cloned rather than extracted from a ZIP — see below.

`tools\run-extension.cmd` is the same thing behind a batch wrapper. It is not
the recommended path and adds nothing on a working setup; it exists because a
`.cmd` is not governed by the execution policy at all, so it still runs on a
machine where the `.ps1` will not. It also prefers `pwsh` when both PowerShells
are installed, and survives a double-click from Explorer, where a `.ps1` opens
in Notepad instead.

If PowerShell refuses the `.ps1`, find out which scope is responsible before
changing anything:

```
Get-ExecutionPolicy -List
```

| Scope showing a restrictive value | Fix |
|---|---|
| `CurrentUser` or `LocalMachine` | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` — no admin needed |
| `MachinePolicy` or `UserPolicy` | Group Policy. `-ExecutionPolicy` **cannot** override these; pipe the script through stdin instead, which the policy does not govern: `Get-Content -Raw tools\run-extension.ps1 \| powershell -NoProfile -Command -` |
| Nothing restrictive, but it still complains | The file carries a mark-of-the-web from being downloaded rather than cloned: `Unblock-File tools\run-extension.ps1` |

## Reading

- **[ARCHITECTURE.md](ARCHITECTURE.md)** — the design, the decisions, and the
  risks written down honestly. Start here.
- **[server/README.md](server/README.md)** — running the server, including
  step-by-step for TrueNAS SCALE.

## Two things worth knowing up front

**Forgetting the master password means losing everything.** That is the design,
not a gap in it. A recovery kit is planned and is not built yet.

**The server holds the vault header** — the KDF parameters and the wrapped vault
key — because a newly enrolled machine needs them to bootstrap. Anyone who takes
that file can attack your master password offline. This is inherent to any
synced vault; Argon2id at 128 MiB is what stands between them and the contents.
Choose the master password accordingly, and do not expose the server to the
internet.

## Licence

MIT — see [LICENSE](LICENSE). Third-party components and their licences are in
[NOTICE](NOTICE); the bundled fonts are OFL and travel with any build that
embeds them.

## Biometric unlock

Optional, and per machine. Without it BENCpass asks for the master password,
which is what it does today and will always keep doing — the fingerprint is a
shortcut, never the only key.

**Nothing to install.** It uses WebAuthn's PRF extension, so the browser asks
the hardware directly: Touch ID on a Mac, Hello on a PC, or a plugged-in FIDO2
key anywhere. No native binary, no entitlement, no developer account, no
annual renewal. Turn it on under the gear in the manager.

You are asked for the master password **once**, at enrolment, and that is not a
formality: the vault key lives in a non-extractable `CryptoKey` once unlocked,
so a second wrapping genuinely cannot be made without re-deriving it. You are
also asked for the fingerprint twice, because Firefox does not hand back the
derived value from the call that creates the credential — measured on both
macOS and Windows — so it has to be read back with a second prompt. The setup
panel says so before it starts.

After that the fingerprint is the way in, not one of two equal options. The
prompt is raised when you arrive at a locked vault, or when something asks to
fill a password; the master password is put away behind a link for when the
reader will not play. Locking deliberately does *not* re-prompt — otherwise the
only way to lock the vault would be to cancel a dialog you did not ask for.

**How it fits together.** The vault key is wrapped twice, under two independent
secrets — the master password, and a 32-byte device secret derived from the
authenticator. Neither wrapping can produce the other. Turning it off drops the
second wrapping locally: nothing is re-encrypted, no other machine is affected,
and the server never knew about it.

| | |
|---|---|
| macOS | Touch ID. The credential is a passkey held by iCloud Keychain, so it is protected by your fingerprint on each device but syncs across the Apple devices signed into that account. Worth knowing rather than assuming: the sync boundary is the iCloud account, not the one Mac. The secret is useless without the vault file it wraps, which is yours |
| Windows | Hello, via the TPM. Machine-bound; it does not sync |
| Linux | nothing, today. `enrol()` asks for a *platform* authenticator, so a plugged-in FIDO2 key — which is a roaming one — is not offered, and there is no built-in equivalent to ask for: the desktop keyrings unlock with your login password, which would make this a way into the vault *without* a password rather than a stronger one. Settings says so rather than offering a switch that fails |

Whether a given machine can actually do it is a fact about that machine, so
there is a probe rather than a promise: `tools/webauthn-probe/README.md`.

### The native host that isn't

`hosts/` holds a native messaging host that is **not used and not installed**.
It was the original design — a small program holding the device secret behind
the OS keystore — and it was built, signed, measured, and then made redundant
by WebAuthn PRF, which reaches the same hardware through the browser with none
of the paperwork. The `nativeMessaging` permission has been removed from the
manifest, so the extension cannot talk to a host even if one were installed.

It is kept because the measurements are the useful part. A macOS keychain item
with a biometric access control needs a `keychain-access-groups` entitlement
that Apple alone authorises; a self-signed certificate embeds it happily and
the kernel then refuses to run the program. That was measured three ways on a
runner rather than reasoned about, and the table is in `hosts/macos/README.md`.
Read `hosts/` as a record of a route that was closed, not as something to run.
