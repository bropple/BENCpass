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
npm install && npm test     # 118 tests; the sync ones build and run the Go server
cd server && go test ./...  # 15 tests

tools/run-extension.sh      # load into a scratch Zen profile, open the test page
tools\run-extension.ps1     # the same, on Windows
npx web-ext lint --source-dir=src --self-hosted
npx web-ext build --source-dir=src --artifacts-dir=dist/ext

tools/preview.sh            # the manager UI, with a throwaway seeded vault
tools/preview.sh shot       # screenshots of every state, into screenshots/
cd server && go run . -dir ./data   # prints a bootstrap enrolment code
```

`npm test` skips the integration tests if no Go toolchain is present, and says
so rather than passing quietly.

**On Windows.** The extension itself is the same `.xpi` — it is browser
JavaScript and contains no platform-specific code — and the Go server
cross-compiles to a static `.exe`. Only the developer tooling differs, and only
`run-extension` has a PowerShell counterpart so far; the rest of `tools/` is
POSIX shell and wants Git Bash or WSL. Windows blocks unsigned scripts by
default, so run it as:

```
powershell -ExecutionPolicy Bypass -File tools\run-extension.ps1
```

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
