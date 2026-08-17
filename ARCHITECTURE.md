# BENCpass — Architecture

A self-hosted, end-to-end encrypted password manager that replaces Firefox's
built-in one, as a Firefox/Zen extension, syncing through a small server you run
yourself.

Status: the crypto core, vault, manager, sync server and extension are built and
running; the native biometric host, the Firefox importer and the recovery kit
are not. Numbers in this document are measurements unless they say otherwise —
the house rule in `style/benco-desktop-app-conventions.md` — and where a figure
has only been taken on one machine, it says which.

---

## 0. Decisions already made

| | |
|---|---|
| Biometric unlock | **Native messaging host from v1**, not deferred |
| Primary accent | **P. Gon blue `#3d7dbf`** — a deliberate departure from the style guide, see §7 |
| Sync server | **Go**, single static binary |
| Transport | **Tailscale primary**, LAN HTTP fallback |
| Sync model | **Per-record**, not one blob |
| Manifest | **MV2** for the persistent background page, see §6 |

---

## 1. Components

```
 ┌─────────────────────────── Firefox / Zen ───────────────────────────┐
 │                                                                     │
 │  background (persistent)          content scripts                   │
 │   ├ crypto core                    ├ form detection                 │
 │   ├ vault state (plaintext,         └ fill / capture                │
 │   │   memory only, never on disk)                                   │
 │   ├ sync engine                   sidebar_action ── browse / search │
 │   └ native host client            popup ────────── fast fill        │
 │                                   options ──────── full manager     │
 └──────────┬───────────────────────────────────────┬──────────────────┘
            │ stdio (JSON)                          │ HTTPS
   ┌────────▼──────────┐                  ┌─────────▼──────────┐
   │ bencpass-host     │                  │ bencpass-server    │
   │ per-OS binary     │                  │ Go, static         │
   │ wraps/unwraps the │                  │ stores ciphertext  │
   │ vault key behind  │                  │ CAS on a sequence  │
   │ biometrics        │                  │ snapshots history  │
   └───────────────────┘                  └────────────────────┘
```

Three deliverables, not one: the extension, the host, the server.

**Local-first is a hard requirement.** Every client keeps a full encrypted
replica in `storage.local`. The vault is fully usable with the server off, on a
plane, or with Tailscale down. Sync is opportunistic. If BENCpass is ever
unusable because a machine in a cupboard is off, the design has failed.

---

## 2. Key hierarchy

```
  master password ──Argon2id──▶ master key ─┐
                                            ├─unwrap─▶ vault key ──▶ records
  biometric secret ──(native host)──────────┘         (AES-256-GCM)
```

Two independent wrappings of the *same* vault key. This is the whole reason for
the indirection:

- changing the master password rewraps one key instead of re-encrypting the
  vault;
- adding, removing or re-enrolling biometrics touches nothing else;
- a new unlock method later is just a third wrapping.

**Argon2id**, via `hash-wasm` — WebCrypto offers only PBKDF2, which is far
weaker per unit of work against a GPU.

Measured on the development machine (Artix Linux, hash-wasm 4.12.0, Node 24.18)
on 2026-08-16. Cost is linear in memory here:

| | |
|---|---|
| 64 MiB, t=3 | 204 ms |
| **128 MiB, t=3** | **399 ms — shipped default** |
| 192 MiB, t=3 | 595 ms |
| 256 MiB, t=3 | 791 ms |
| 128 MiB, t=4 | 527 ms |

Memory is raised in preference to iterations, because memory is the axis a GPU
or an ASIC finds expensive and iterations are cheap to parallelise.

**This number has not yet been taken on the slowest machine in the fleet**,
which is the one that decides whether the default is tolerable. Re-measure
there. Parameters travel with the vault, so raising them later does not strand
an existing vault.

Import the vault key as a **non-extractable `CryptoKey`** so its bytes never
exist in JS memory. You cannot reliably zero a `Uint8Array` in JavaScript — so
don't claim to, and keep as little raw key material in JS as possible.

**PBKDF2 fallback:** none. If WASM is unavailable the vault does not open. A
silent downgrade to weak KDF parameters is worse than a clear failure.

---

## 3. Data model

One record per credential. Never one blob — see §9 for why this is the single
most important decision in the document.

```jsonc
{
  "id":      "uuid-v4",         // stable, never reused
  "rev":     17,                // per-record, monotonic, client-incremented
  "deleted": false,             // tombstone; never hard-delete on the server
  "nonce":   "<12 random bytes>",
  "ct":      "AES-256-GCM(vaultKey, nonce, plaintext, aad = id || rev)"
}
```

### Timestamps, and why they do not decide merges

Four timestamps live *inside* the ciphertext, so the server never learns them.
They map one-for-one onto what Firefox already records, which makes the importer
lossless:

| BENCpass | Firefox | Meaning |
|---|---|---|
| `created` | `timeCreated` | first saved |
| `updated` | — | any field last changed |
| `passwordChanged` | `timePasswordChanged` | the password specifically last changed |
| `lastUsed` | `timeLastUsed` | last filled |
| `timesUsed` | `timesUsed` | fill count |

`updated` and `passwordChanged` must stay distinct. Only the second one can
answer "this password is three years old", which is the whole point of an age
audit, and a metadata edit must not reset it.

**None of these decide a merge.** Client wall clocks drift, and a machine with a
badly wrong clock would win every last-writer-wins tiebreak indefinitely — in
the direction of resurrecting a password you had already rotated away from, and
silently. Merges are decided by causality instead (§4).

Timestamps are for display, for age and reuse audits, and as a final tiebreak
only when two sides are otherwise indistinguishable. On import, a value more
than a few minutes in the future is clamped to now and the original kept for
display, because a bad clock somewhere upstream should not produce a record
dated 2049.

The **AAD binding of `id || rev` is not optional.** Without it a hostile or
compromised server can swap ciphertexts between records or replay an old
revision, and the client cannot tell. With it, either attack fails to decrypt.

Plaintext, once decrypted. A `type` discriminator selects the field set:

```jsonc
// type: "login"
{
  "type": "login",
  "title": "...", "urls": ["https://..."],
  "username": "...", "password": "...",
  "totp": "otpauth://...", "notes": "...",
  "fields": [{ "name": "...", "value": "...", "hidden": true }],
  "history": [{ "password": "...", "changed": 1755200000000 }]
}

// type: "address"
{
  "type": "address",
  "title": "Home", "name": "...", "organization": "...",
  "address-line1": "...", "address-line2": "...",
  "address-level2": "...",   // city
  "address-level1": "...",   // state / province — absent in much of Europe
  "postal-code": "...",
  "country": "GB",           // ISO 3166-1 alpha-2
  "tel": "...", "email": "...", "notes": "..."
}
```

### Why a second type costs almost nothing

`crypto.js` seals opaque bytes and `merge.js` works on envelopes, so neither has
any opinion about what a record contains. Sharing one vault means one key, one
unlock, one sync, one conflict model. Only the model and the UI are type-aware.

The discriminator went in before any real vault existed, deliberately — adding
it afterwards would be a format migration for the sake of a field that costs
nothing today.

**Address fields carry the WHATWG autofill token names verbatim**, hyphens and
all, rather than being translated into camelCase. It reads worse and it is the
right trade: the fill code takes a token off the page's `autocomplete` attribute
and looks it up directly, with no mapping table in between. A mapping table is a
second place for the field set to drift, and drift there surfaces as a form that
silently half-fills.

One flat address type, not a separate "identity" record: shipping forms ask for
the name, the phone and the address together, and splitting them would mean
filling one form from two records.

**No payment card type, by decision.** Card data carries a materially different
threat model and compliance surface for very little convenience gained, and the
browser and the OS already store cards. Addresses are PII and get the same
encryption as everything else — that is free — but a card number is not going in
here.

Address autofill is subject to the same rule as passwords: **never fill without
an explicit user action.** Hidden address fields are a known harvesting vector,
and being less catastrophic than a leaked password does not make it acceptable.

`history` is the safety net. It means a bad merge is recoverable rather than
fatal, and it costs almost nothing. Cap it at ~20 entries per record.

**Metadata the server learns anyway:** how many records exist, and when each one
changes. That is acceptable for a box on your own tailnet, and it is stated here
rather than quietly ignored.

---

## 4. Sync

The server is deliberately dumb. It stores ciphertext, hands out a monotonic
sequence number, and refuses out-of-date writes. It does no merging, because it
cannot — it has no key. All merge logic is client-side.

```
GET  /v1/records?since=<seq>     → { seq, records[] }
PUT  /v1/records                 → { seq } | 409
     If-Match: <seq>               body: { records[] }
GET  /v1/meta                    → { kdfParams, wrappedVaultKey, seq }
POST /v1/enroll                  → device registration, one-time code
```

Every request is signed with a **per-device HMAC key** issued at enrollment.
Revoking a lost laptop is deleting one device key, not rotating the vault.

**Merge rule** — causal, not chronological. Each client keeps a `syncedRev` map:
for every record, the `rev` it last agreed with the server on. That is the
common ancestor, and it is the only thing needed to tell an edit from a
divergence.

```
base = syncedRev[id]        // may be absent: the record is new to one side

local.rev == remote.rev  →  in sync ONLY IF the ciphertext also matches
local.rev  == base       →  fast-forward, take remote
remote.rev == base       →  keep local, push it
otherwise                →  genuine concurrent edit → keep BOTH as a conflicted
                            copy, surface it in the UI, never pick silently
```

**Equal revision numbers do not mean equal content**, and assuming they did was
a real bug caught by the integration test rather than by the unit tests. `rev`
is a per-record counter incremented locally, so two machines that both edit a
record at rev 1 both arrive at rev 2 with different passwords. The merge saw
matching numbers, reported "in sync", and silently dropped one edit. The
ciphertext is the authority; the number is only a hint.

The unit tests missed it because they constructed both sides with the same
synthetic ciphertext — a fixture that quietly encoded the assumption under
test. Hence the integration suite runs against the real Go binary.

Then: tombstones win over edits, but the body is retained server-side for the
snapshot window so an accidental delete is recoverable. Push, retry once on a
fresh 409, and surface the failure rather than looping.

This is correct under arbitrary clock skew, needs one extra map in local state,
and degrades to "take the other side" in the common case where only one machine
touched a record. Timestamps are consulted only to break a tie between two sides
that are otherwise identical.

**Anti-rollback:** the client stores the highest `seq` it has ever seen and
**refuses any response with a lower one**. Without this a LAN attacker can serve
you last month's vault — including a password you have since rotated away from.

**Server-side snapshots** on every write, keep N (default 50). This is the
backstop for a client bug that pushes garbage, and it is cheap.

### Transport

**Tailscale is the primary path.** `tailscale cert` yields a real Let's Encrypt
certificate for `host.tailnet.ts.net`, which means valid TLS with no warnings,
no private CA to distribute to every machine, and the same endpoint working on
the LAN and from outside it. There is no second configuration to maintain.

**LAN fallback is plain HTTP, and that is a considered choice.** The E2E
encryption is the real security boundary; TLS is defence in depth. Self-signed
certificates on a bare LAN IP are the worst of both worlds — `fetch()` from an
extension fails outright with no click-through, and the workaround (open the URL
in a tab, accept the exception) is fragile and per-profile. HMAC request signing
plus the anti-rollback rule covers what TLS would have on that path.

---

## 5. Native host

One JSON-over-stdio protocol, three platform implementations. The host is a
**key-wrapping oracle and nothing else** — it never sees a password, never talks
to the network, and holds no vault state.

```jsonc
→ { "op": "wrap",   "key": "<base64 vault key>" }
← { "ok": true, "blob": "<base64>" }
→ { "op": "unwrap", "blob": "<base64>" }      // prompts for biometrics
← { "ok": true, "key": "<base64>" } | { "ok": false, "err": "cancelled" }
→ { "op": "caps" }
← { "ok": true, "biometric": true, "kind": "touchid" }
```

| OS | Mechanism | Language |
|---|---|---|
| macOS | Keychain item with `kSecAccessControlBiometryCurrentSet`, gated by LocalAuthentication | Swift, or Go + cgo |
| Windows | `KeyCredentialManager` — a Hello-gated key signs a fixed challenge; RSA PKCS#1 v1.5 is deterministic, so the signature is stable key material | C#/WinRT or C++/WinRT |
| Linux | **No biometric equivalent exists.** libsecret/kwallet, or decline and fall back to the master password | Go |

`kSecAccessControlBiometryCurrentSet` — not `...BiometryAny` — so enrolling a
new fingerprint invalidates the wrap and forces a master-password re-unlock.
That is the correct behaviour: someone who can add a finger should not inherit
the vault.

**Linux is the development machine and gets no biometrics.** Do not let that
turn into an untested master-password path — it is the path you will personally
use every day, and it is also the fallback on every platform when a sensor is
unavailable, wet, or the user cancels.

### Installation

Firefox native messaging needs a manifest naming the extension ID, at a
per-OS path, with a registry key on Windows pointing at it. Consequences:

1. **Fix the extension ID before writing any other code** —
   `browser_specific_settings.gecko.id`, e.g. `bencpass@ropple.net`.
2. The host installer writes that manifest. Zen may use a different profile
   root than Firefox — **verify the path on Zen specifically** rather than
   assuming Firefox's.
3. Packaging follows `style/benco-build-and-packaging.md`: static linking,
   the self-containment assertion per platform, ad-hoc signing on macOS after
   assembly.

---

## 6. Extension

**MV2, for now.** Firefox still supports it, and it buys a genuinely persistent
background page — which is where the unlocked vault key lives. Under MV3 the
event page is terminated at the browser's discretion and the key evaporates
mid-session. If MV2 is ever withdrawn, the migration is `storage.session`
(memory-only, cleared on browser restart) plus a long-lived `runtime.Port` held
open from an extension page to keep the worker alive. Note the cost now so it
isn't a surprise later.

**CSP:** Argon2's WASM needs `'wasm-unsafe-eval'` declared in
`content_security_policy`. Fonts must be bundled as local woff2 — extension CSP
forbids a CDN, so VT323 and Share Tech Mono ship inside the `.xpi`.

### The trust boundary, and what a review found in it

The content script shares a process and a DOM with whatever the page is. It is
the least trusted component, and the invariant is:

> **The content script never receives a password it did not already have.**

It is told what entries *exist* for its frame — titles and usernames, enough to
draw a menu. A secret crosses to it as the single value being filled, after the
user has picked an entry, and after the background has re-derived the frame's
origin from `sender` rather than believing the frame's account of itself.

A security review of the first cut found five gaps worth recording, because
four of them were the same mistake:

| | |
|---|---|
| `SEARCH` had no caller check | an empty query returns the whole vault index |
| `STATE` had no caller check | leaks the active tab's host — a live browsing feed |
| `UNLOCK` had no caller check | a master-password verification oracle |
| addresses skipped every check | a home address to any third-party frame |
| the session id sat in the iframe `src` | page-readable; see below |

The first four were per-handler guards that were simply forgotten on six of
eleven handlers. The fix is **one allow-list at the single message entry point**
naming the three types a content script may send, rather than a check inside
each handler that the next handler can omit.

Worth stating precisely: in Firefox MV2 a page cannot call
`browser.runtime.sendMessage` at all — content scripts run in an isolated world
— so those four need a compromised content script rather than merely a hostile
page. They are still fixed, because the guards were plainly intended and this is
a password manager.

The fifth was reachable from ordinary page script. The session id was in the
iframe's `src`, and that element lives in the page's own DOM, so the page could
read both it and the extension's UUID. `overlay.html` is web-accessible, so the
page could then open **its own privileged copy** against that session — which
satisfies every "is this an extension page" check — and clickjack a fill out of
it. The id is now handed over by `postMessage` to the frame's cross-origin
`contentWindow`, which the page cannot listen to, and `web_accessible_resources`
is narrowed to `overlay.html` alone.

### What a page-embedded extension frame cannot do

Measured against Firefox, not assumed, after three attempts to be cleverer:

| from | result |
|---|---|
| `sidebarAction` in the overlay | **absent** — not exposed to an extension page framed in a web page |
| `browserAction` in the overlay | **absent**, for the same reason |
| `sidebarAction.open()` in the background | *"may only be called from a user input handler"* |
| `browserAction.openPopup()` with hidden chrome | resolves and shows nothing |

The boundary is closed in both directions: the document that receives the click
has no chrome APIs, and the contexts that have them have no user gesture. **No
click originating in a page can open a sidebar or a popup.**

What does work is a keyboard command, because Firefox handles the keypress
itself rather than handing it to an extension: `_execute_sidebar_action`, bound
to `Alt+Shift+B`. That is why the sidebar has a shortcut and not a button.

The in-page unlock row therefore opens the manager in a tab — and the background
closes that tab and returns to the originating page as soon as the vault opens,
so the detour does not have to be tidied up by hand.

### Autofill — the largest and least glamorous part

Two rules that are not negotiable:

- **Never autofill on page load.** Fill on explicit click or keyboard shortcut
  only. Silent fill is a credential-harvesting vector via hidden forms and
  third-party iframes, and it is how password managers get CVEs.
- **Match on eTLD+1 via the Public Suffix List**, plus an equivalent-domains
  table for the `amazon.com`/`amazon.co.uk` case. `hostname.endsWith("google.com")`
  also matches `evil-google.com`.

The long tail, all of which will be hit: shadow DOM, cross-origin login iframes,
SPA forms that appear after load, two-step username-then-password flows, and
React controlled inputs that ignore `el.value = x` unless you call the native
setter and dispatch a real `input` event.

Content scripts run in an isolated world, so page JS cannot read extension
state. Do not weaken that — put nothing decrypted into the page beyond the one
field the user chose to fill.

### Replacing the built-in manager

- `browser.privacy.services.passwordSavingEnabled` — **verify this works in
  Zen.** Fallback is telling the user to untick "Ask to save logins" in
  preferences by hand, and saying so plainly in the README.
- **Import** from the `about:logins` CSV export and from `logins.json`.
- **Build export before import.** Never ship a vault someone cannot get out of.
  An unencrypted CSV export is a footgun, so make it a deliberate, warned act.

### Recovery

Forgetting the master password means everything is gone, by design. So a
recovery kit is generated at setup — a recovery code plus an encrypted backup,
formatted to be printed. The 40-column ASCII receipt conventions in the design
guide §5 suit this exactly.

### Distribution

Release Firefox and Zen require a Mozilla-signed `.xpi`. Submit to AMO as
**unlisted** — free, not publicly listed, and yields a signed file to install on
your own machines. `xpinstall.signatures.required=false` only works on Developer
Edition and ESR and is not the plan.

### Smaller things, all real

- Clipboard auto-clear after ~30 s, and say in the UI that a clipboard manager
  will still have captured it.
- Password generator uses `crypto.getRandomValues` with **rejection sampling**.
  Modulo introduces bias.
- Auto-lock on a timer and on system suspend.

---

## 7. Palette — a documented departure

The style guide names canonical green `#78b946` as the primary accent
everywhere. BENCpass leads with **P. Gon blue** instead, because the mascot is
P. Gon and because a password manager needs its accent free of semantic duty.

Green is not discarded — it is **promoted to meaning**:

| Role | Hex | Source |
|---|---|---|
| Primary accent / CTA | `#3d7dbf` | P. Gon fill |
| Accent edge / pressed | `#254d75` | P. Gon edge |
| Base background | `#080d14`, `#0c1420` | derived — blue-tinted near-black |
| Panel background | `#141d2a` | derived |
| Primary text | `#c3d9ee` | derived — blue phosphor |
| Secondary text | `#7d93a8` | derived |
| Border | `#1e2c3d` | derived |
| **Strong / safe / unlocked** | `#78b946` | canonical green |
| **Reused / weak / warning** | `#e8b23d` | guide amber |
| **Breached / error / locked** | `#d84a3a` | guide alert red |

The derived values mirror the green palette's structure step for step, so the
two sit together as obviously the same system in a different key. Everything
else in the guide holds unchanged: never pure black, 1px dim borders, 2–4px
radii, flat buttons, `letter-spacing: 1px` on headings and labels only, one
glowing title per screen, no animation, no gradients.

**Update the style guide's roster rule** to record that P. Gon's colours are now
claimed by an application as well as a character.

---

## 8. Phasing

Nothing here is useful until it can store and retrieve one password, so that is
the first milestone rather than the fourth.

1. **Crypto core + local vault.** Argon2id, key hierarchy, per-record AES-GCM,
   `storage.local` replica. No sync, no server, no fill. Unit-tested against
   known vectors.
2. **Manager UI.** Full CRUD, search, generator, lock/unlock, the palette. This
   is the point at which it is usable by hand.
3. **Server + sync.** Go binary, CAS, snapshots, merge, anti-rollback,
   Tailscale. Two machines.
4. **Autofill + capture.** Content scripts, PSL matching, the in-page overlay
   iframe, the long tail. Address filling rides on the same machinery with a
   different field taxonomy, so it lands here rather than earning its own step.
5. **Native host.** macOS and Windows biometrics, Linux fallback.
6. **Import/export, recovery kit, replacing the built-in manager.**

Export lands in step 2, not step 6 — the vault should never be a place data can
only go into.

---

## 9. Risks, honestly

**A single encrypted blob would eventually eat a password.** Two machines edit
while one is offline, the later push clobbers the earlier, and the server cannot
help because the payload is opaque to it. This is the reason for per-record
records, per-record revisions, conflicted copies, and password history. It is
the one decision here that is not worth revisiting for simplicity.

**Autofill is roughly 60% of the total work** and none of it is interesting. It
is also the part that determines whether the thing actually gets used, because a
password manager that does not fill is a text file with extra steps.

**Biometrics could still turn out to be theatre if built carelessly.** A
fingerprint prompt in front of a key that was already sitting in `storage.local`
proves nothing. The security property comes from the OS keystore genuinely
refusing to release the wrapping key without the sensor — verify that by
checking the wrap is unusable after the process is killed and biometrics are
declined, not by observing that a prompt appeared.

**Prior art exists.** Vaultwarden plus the Bitwarden extension covers this
feature set today. Building it anyway is a legitimate choice — ownership, taste,
and a house aesthetic are reasons — but it should be a choice made with that
known, not discovered at step 4.

**This is the thing that holds every password.** Which argues for: an export
path that always works, snapshots on the server, `history` on every record, a
printed recovery kit, and keeping Firefox's built-in manager populated until
BENCpass has been trusted for a while. Turn it off last, not first.
