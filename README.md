<!-- BENCpass -->

# BENCpass

A self-hosted, end-to-end encrypted password manager for Firefox and Zen, meant
to replace the browser's built-in one. Your vault syncs between your own
machines through a small server you run yourself — on a NAS, a spare box, or
anything else that stays on.

The server stores ciphertext and holds no key. It cannot read a record, and
because it cannot read one, it cannot merge either — all merging happens on the
clients.

> **Not finished.** Everything below the line works and is tested, and the
> extension now loads and fills. Still missing: the native biometric host,
> import from Firefox, and the recovery kit. Until a recovery kit exists,
> forgetting the master password loses the vault with no way back — so keep
> Firefox's own password manager populated in parallel for now.

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
| ⬜ Native host: Touch ID / Windows Hello | — |
| ⬜ Import from Firefox, recovery kit | — |

## Layout

```
src/core/     crypto, vault, merge, sync — no browser APIs, tested under Node
src/ui/       the manager page
src/vendor/   Argon2 (hash-wasm), vendored as one ES module
server/       the Go sync server
tools/        preview harness, icon and build scripts
test/         Node tests, including integration tests against the real server
```

## Running things

```sh
npm install && npm test     # 159 tests; the sync ones build and run the Go server
cd server && go test ./...  # 15 tests

tools/selftest.sh           # drive the extension in a real browser, unattended
tools/run-extension.sh      # load into a test profile, open the form-shapes page
tools/run-extension.sh fresh   # ...discarding the previous test vault
tools/run-extension.sh verbose # ...logging what the browser itself prints
tools\run-extension.ps1     # the same on Windows; -Fresh to discard
npx web-ext lint --source-dir=src --self-hosted
npx web-ext build --source-dir=src --artifacts-dir=dist/ext

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

If a run ends in `Error: connect ECONNREFUSED 127.0.0.1:<port>`, that is not the
test server — it is `web-ext` giving up on the browser. It launches the browser
with `-start-debugger-server <port>` and then dials that port for thirty
seconds; the message means the browser started but never listened. Run
`tools/run-extension.sh verbose` and read the `Firefox stderr:` lines, which say
why. Two causes account for most of it: the browser refuses the debugger server
outright, or the profile could not be opened and it exited. `tools/selftest.sh`
is a useful second data point, since it uses a throwaway profile and headless
mode — if that connects and `run-extension.sh` does not, the profile is the
difference, and `tools/run-extension.sh fresh` clears it.

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
