# Notes for reviewers

BENCpass is a password manager. The vault is encrypted on the client and the
add-on has no backend of its own: there is no BENCpass service, no account, and
no address the extension talks to that the user did not type in themselves.

This file answers, in advance, the questions the source raises. If something
here is wrong or insufficient, it is an oversight rather than an evasion; the
fastest way to reach a human is an issue on the repository above, or the
developer account this was submitted from.

**Submission:** unlisted / self-distribution.
**Source:** https://github.com/bropple/BENCpass

---

## What leaves the browser

With no server configured — the default, and a fully working state — **nothing**.
The extension makes no network request at all. There is no telemetry, no error
reporting, no update ping, no analytics.

If the user configures a sync server, the extension sends that server encrypted
records. The declaration is:

```json
"data_collection_permissions": {
  "required": ["none"],
  "optional": ["authenticationInfo", "personallyIdentifyingInfo", "browsingActivity"]
}
```

`required: none` because the add-on is complete and useful with no server, and
in that state transmits nothing.

`optional` names what sync carries when the user sets one up: passwords
(`authenticationInfo`), the names, addresses, phone numbers and email in address
records (`personallyIdentifyingInfo`), and the site addresses saved against each
login (`browsingActivity`).

That third one is declared on the literal reading rather than the comfortable
one. A login record carries the URLs it applies to, and the category covers
"information about the websites users visit, such as specific URLs". It would be
arguable that a site address is part of the credential rather than browsing
data — you cannot have a password manager entry without knowing what it is for —
but a list of the sites someone holds accounts on is what the words describe, so
it is declared. No browsing history, no visit records, and no page content is
collected or transmitted: only the addresses the user attached to an entry.

These are requested at runtime with `permissions.request({ data_collection })`
at the moment a server address is entered, and a refusal means the address is
not saved. They are therefore visible and revocable in about:addons under
Permissions and Data, which would otherwise show them off while the vault
synced.

Both are declared **even though the server receives only ciphertext and never
holds a key**. The policy is about the boundary rather than the destination —
"any data collected, used, transferred, shared, or handled outside the add-on or
the local browser" — and a server the user runs is still outside the browser.
Declaring less on the grounds that it is encrypted, or that the server belongs
to the user, would be reading the rule for what it permits rather than for what
it asks.

The endpoint is user-entered, stored in `browser.storage.local`, and is the only
host the extension ever contacts. Every network call in the package is in
`src/core/sync.js` and goes to that address; `src/ui/manager.js` additionally
calls `<endpoint>/v1/health` when the user presses **Test** beside the field.

---

## Permissions

| Permission | Why |
|---|---|
| `storage` | the encrypted vault and settings, in `storage.local` |
| `tabs` | to resolve which page a fill is for, and to close the manager tab after unlocking |
| `idle` | auto-lock on system idle, alongside the timer |
| `notifications` | the fallback "save this password?" prompt when the in-page one cannot be shown |
| `menus` | the right-click "generate a password" item |
| `<all_urls>` | a password manager has to offer credentials on the sites they belong to, and those sites are not knowable in advance |

`<all_urls>` is the one worth justifying. The content script classifies form
fields and draws an anchor; it never receives a stored password until the user
picks an entry from a menu rendered in a cross-origin extension frame the page
cannot read or click into. Origin matching is registrable-domain based against a
vendored Public Suffix List (`src/core/match.js`, `src/vendor/psl.js`), so a
credential for `example.com` is never offered to `evil-example.com`,
`example.com.evil.com`, or a punycode homograph.

`tools/check-permissions.mjs` fails CI if any requested permission has no call
site, which is how `nativeMessaging` was caught after the component that needed
it was removed.

---

## Generated and minified files, and how to reproduce them

Three files in the package are not hand-written. Each has a script in the
repository that regenerates it. CI fails if `argon2.js` or the country table
drifts from what its script produces; the Public Suffix List cannot be checked
that way and is handled differently — see below.

### `src/vendor/argon2.js` — Argon2id (minified)

Verbatim `hash-wasm@4.12.0`'s `dist/argon2.umd.min.js`, with a provenance header
prepended and one export appended — that is the whole delta, and both ends are
readable in the file. The WASM is inlined as base64 by upstream, not by us.

```sh
npm ci                 # hash-wasm is integrity-pinned in package-lock.json
tools/vendor.sh        # writes src/vendor/argon2.js
git diff --exit-code -- src/vendor/argon2.js   # byte-identical
```

The last two lines run in `.github/workflows/security.yml`, so a tampered copy
fails the build. Both ends of the delta are visible in the file — the provenance
header at the top, the export at the bottom — and the UMD wrapper in between
finds no `exports` and no `define` inside an ES module, so it takes its global
branch.

It is vendored rather than imported because an extension cannot resolve a bare
specifier and cannot use an import map — that needs an inline
`<script type="importmap">`, which the extension CSP forbids.

### `content_security_policy` and `'wasm-unsafe-eval'`

```
default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self';
img-src 'self'; font-src 'self'; connect-src *; frame-src 'self'
```

`default-src 'none'` is the base: nothing is permitted that is not named
afterwards.

`'wasm-unsafe-eval'` is required to instantiate the Argon2 WASM module and
nothing else. It does not permit `eval`, `new Function`, or inline script —
`script-src 'self'` still governs JavaScript. There is no `unsafe-inline` and no
`unsafe-eval` anywhere in the package.

`connect-src *` is the one open directive, and it is open because the sync
endpoint is an address the user types in. No other directive allows a remote
origin, and none allows `data:` — scripts, styles, images, fonts and frames are
all `'self'`.

Argon2id is the key derivation function for the master password — 128 MiB, t=3.
A JavaScript implementation at that memory cost is not viable.

### `src/vendor/psl.js` — Public Suffix List

Fetched from publicsuffix.org, with the rule count and retrieval date recorded in
its header.

```sh
tools/vendor-psl.sh
```

**Not reproducible byte-for-byte, and deliberately not CI-checked.** The list is
a living document: re-running the script fetches whatever publicsuffix.org
serves today and stamps today's date, so a drift check would fail whenever the
world changed rather than whenever this repository did. The committed copy
records what was fetched and when, and refreshing it is a deliberate act with a
visible diff.

Used for origin matching, so that `foo.github.io` and `bar.github.io` are treated
as different sites in both directions.

### The country table in `src/core/address.js`

Generated from the ICU data in Node, for the address-form country dropdown.

```sh
node tools/gen-countries.mjs           # regenerate
node tools/gen-countries.mjs --check   # verify, as CI does
```

---

## No remote code

The package contains no call to `eval`, `new Function`, `document.write`,
`innerHTML`, `insertAdjacentHTML`, or `Range.createContextualFragment`.

Grepping for the five DOM names returns exactly one line — a comment in
`ext/toast.js` noting that the sentence below it is built without `innerHTML`.

Grepping for `eval` returns more, and none of it is a call, so here is what you
will see and what each is:

| Where | What |
|---|---|
| `manifest.json` | `'wasm-unsafe-eval'` in the CSP, for the Argon2 WASM — see above |
| `ext/webauthn.js` ×2 | `prf: { eval: { first: SALT } }` — the name of a WebAuthn PRF extension field, not a function |
| `core/argon2.js`, `ui/manager.js` | prose in comments |

All rendering of record data goes through `textContent` or `createTextNode`,
including data arriving from the import feature, so a record whose title is
`<img onerror=...>` renders inert.

No script is fetched at runtime. Everything executed ships in the package.

---

## `web_accessible_resources`

```json
["ext/overlay.html", "ext/toast.html"]
```

These are the credential menu and the "save this password?" prompt. They are
extension pages framed into web pages deliberately, so that the page cannot read
their contents or synthesise a click inside them — the alternative, drawing them
into the page's own DOM, would put usernames within reach of the site.

A hostile page can frame them. What it cannot do is act through them: every
privileged message they send carries a 128-bit session or notice id, generated
by the background page and delivered to the frame by `postMessage` to a
cross-origin `contentWindow`. The id is never placed in a URL, `src`, or DOM
attribute. The background validates it against a session it created, and
re-checks the target origin from `sender` — never from the message — before any
value is filled.

The master password is deliberately never accepted in an in-page frame. A site
can draw a convincing imitation of that menu, so the real one sends the user to
the sidebar or the manager instead, which a page cannot draw over.

---

## Building the package from source

```sh
git clone https://github.com/bropple/BENCpass
cd BENCpass
npm ci
npx web-ext build --source-dir=src --artifacts-dir=build/ext
```

`src/` is the extension exactly as submitted; nothing is transformed, bundled or
minified at build time. The tests are `npm test` (Node, no browser) and
`cd server && go test ./...`.

---

## The server is not part of this submission

`server/` is a small Go program the user may optionally run on their own machine
to sync between their own devices. It is not bundled, not downloaded by the
extension, and not required. It stores ciphertext and holds no key, so it cannot
read a record even in principle.

It is in the repository because the sync protocol has two ends and both should be
readable. Its wire format is documented in `ARCHITECTURE.md` §4.

---

## The rescue tool is not part of this submission either

`rescue/` is a small Go program a user may optionally download to open their own
vault when this add-on cannot be reached — a profile that will not load, or a
machine that is gone. It is not bundled, not downloaded by the extension, and
not required.

It reads two things: the encrypted backup the add-on can write (Settings → Your
data), and a sync server's data file. It is read-only, makes no network request
of any kind, and cannot unlock anything without the master password or the
recovery code.

It is in the repository because the vault format now has two implementations and
both should be readable. The tests are cross-language for that reason: the Go
fixtures are sealed by `src/core/` itself, and its exports are read back by
`src/core/transfer.js`, so the two cannot drift unnoticed.

## Things a reviewer may notice, answered

**MV2.** The unlocked vault key lives in a persistent background page and is a
non-extractable `CryptoKey`. Under MV3 the event page is terminated at the
browser's discretion and the key would evaporate mid-session. The migration path
is noted in `ARCHITECTURE.md` §6.

**`hosts/`.** A native messaging host that was built, measured, and abandoned when
WebAuthn PRF replaced it. It is **not shipped** — it is outside `src/`, is not in
the package, and the `nativeMessaging` permission has been removed, so the
extension cannot talk to a host even if one were installed. It is kept as the
record of a dead end, and `README.md` says so.

**A `.zip` in GitHub releases is unsigned.** Only the signed `.xpi` from this
submission is intended for installation; the CI artefact exists so the build is
reproducible and testable.

---

## Trying it

No account or server is needed.

1. Install and open the manager (toolbar icon → **Manage**, or the sidebar).
2. Create a vault with any master password.
3. Visit any login form. The field gets a small anchor; clicking it offers a
   generated password, and submitting the form offers to save it.
4. **Settings → Your data → Export** writes the vault out as JSON or CSV, which
   also shows exactly what is stored.

Sync, biometric unlock and the server are all optional and off until configured.
