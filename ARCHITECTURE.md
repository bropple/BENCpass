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
| Biometric unlock | **WebAuthn PRF, no native component.** A host was built first; see §5 |
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
 │   └ WebAuthn PRF                  popup ────────── fast fill        │
 │                                   options ──────── full manager     │
 └──────────┬───────────────────────────────────────┬──────────────────┘
            │ navigator.credentials                 │ HTTPS
   ┌────────▼──────────┐                  ┌─────────▼──────────┐
   │ the browser's own │                  │ bencpass-server    │
   │ authenticator     │                  │ Go, static         │
   │ Touch ID, Hello,  │                  │ stores ciphertext  │
   │ a security key —  │                  │ CAS on a sequence  │
   │ nothing of ours   │                  │ snapshots history  │
   └───────────────────┘                  └────────────────────┘
```

Two deliverables: the extension and the server. The fingerprint needs no
component of ours at all — see §5.

**Local-first is a hard requirement.** Every client keeps a full encrypted
replica in `storage.local`. The vault is fully usable with the server off, on a
plane, or with Tailscale down. Sync is opportunistic. If BENCpass is ever
unusable because a machine in a cupboard is off, the design has failed.

---

## 2. Key hierarchy

```
  master password ──Argon2id──▶ master key ─┐
                                            ├─unwrap─▶ vault key ──▶ records
  biometric secret ──(WebAuthn PRF)─────────┘         (AES-256-GCM)
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
  "n":       "<12 random bytes>",  // the wire field is "n", not "nonce"
  "ct":      "AES-256-GCM(vaultKey, n, plaintext,
                          aad = 'bencpass:v2:rec:{id}:{rev}:{0|1 deleted}')"
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

The **AAD binding of `id || rev || deleted` is not optional.** Without the
first two a hostile or compromised server can swap ciphertexts between records
or replay an old revision, and the client cannot tell. Without the third,
`deleted` is a cleartext claim nobody signed: merge runs on a locked vault and
routes by that flag, and whoever holds the file — or the server — could flip
it with no key at all. Bound, each of those attacks fails to decrypt. The
sealer reads the AAD bit off the body itself, so the envelope flag and the
sealed truth cannot be written to disagree; a reader that hits a broken seal
retries the only other claim the envelope could have made, which either proves
the flag was flipped (an attack there is policy for: refuse it, or park the
body for a person) or confirms real damage. Both attempts authenticate the
full AAD, so nothing is ever believed that the sealer did not sign.

The format number (`2`, in the vault header and in every AAD) versions the
cryptography itself, and there is exactly one. Format 1, which left `deleted`
outside the AAD, is refused by name rather than opened by a compatibility
branch — a reader that accepts an older AAD is a downgrade path, and no
format-1 vault exists outside this repository's history (v0.11.0 shipped it,
nobody ran it).

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

**The record stores the granular fields and derives the composite ones.** First
name and last name, not a full name; three street lines, not one block; a
country code, not a country name. Joining is exact and splitting is a guess, so
storing the parts means every shape a form might ask for can be produced, while
storing the whole loses the parts the moment a site wants "First name" and all
that was kept is "Ben Ropple". `src/core/address.js` holds the schema, the
derivations and the reverse for capture; the manager's editor, the record's
keys, and what the fill code looks up are all the same list, so none of the
three can drift.

**A form is answered with exactly the tokens it has fields for.** The content
script sends the group's tokens with its request for candidates, and the
background derives those and only those. A checkout with a postcode box and
nothing else is not handed a phone number — not because the fill code would
decline to use it, but because it never leaves the vault. A token that cannot
be derived honestly is omitted rather than guessed: an area code is only
offered for a number whose plan makes the split unambiguous.

**An address belongs to the person, not to a site.** Logins are filed under the
host they were captured from, because that is what identifies them. An address
is not: the same one is used at every shop. So it is named — "Home", "Work" —
and every named address is offered on every checkout. Saving under a name that
already exists updates that address rather than adding a second one beside it,
because three entries called "Home" cannot be told apart in a menu. Titling
captured addresses with the host was the first cut, and it produced a vault of
near-identical addresses named after shops.

**Where a value has more than one correct spelling, the fill picks.** The
background sends the value and its alternatives; only the content script can
see the element, so only it can choose between them. A `<select>` is matched
against its options. A text box is matched against its `maxlength`, which is
the honest answer to the phone-number problem: `tel` means the full number
including the country code, but plenty of forms have a single Phone box sized
for the domestic form, and rather than guess at a page's assumed country we
take the field at its word — if `+1 (415) 555-0132` does not fit and
`(415) 555-0132` does, the shorter one is what was being asked for. Likewise
`autocomplete="country"` gets the ISO code, while a box merely *labelled*
Country gets the country name, since that is what a person would type into it.

**Dropdowns are filled by matching an option, never by assignment.** Setting
`value` on a `<select>` to a string no option carries selects nothing at all,
which leaves the form looking answered when it is not. So the option is found
first — against its value and its text, exactly and then folded for accents and
punctuation — and the element is left alone if none matches. Country and state
alternatives (`US`, `United States`, `USA`) travel with the value for this
reason alone.

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
PUT  /v1/meta                    → { seq } | 409
     If-Match: <seq>               body: { meta }
POST /v1/codes                   → { code, ttlSeconds }
POST /v1/enrol                   → device registration, one-time code
```

Every request is signed with a **per-device HMAC key** issued at enrolment.
Revoking a lost laptop is deleting one device key, not rotating the vault.

### What is signed

```
HMAC-SHA256( METHOD \n host \n /path?query \n unix-millis \n nonce \n If-Match \n sha256(body) )
```

Four of those seven are there for reasons worth stating, because each closes
something the others do not:

**`nonce`** — the server accepts each one once, remembering them for as long as
the clock window. Without it a captured request could simply be sent again
inside those five minutes. Compare-and-swap on the sequence covers a replayed
record write, since the second one loses the race, but not every authenticated
request is a write: minting an enrolment code returns a *fresh* code every time
it is called, so a replayed mint used to hand out as many device keys as anyone
cared to ask for. The nonce is what makes the LAN address safe to expose.

**`host`** — a client holds two addresses for one server and moves between them.
Whatever answers the first address can read a complete signed request and then
drop the connection: the client sees an unreachable address, succeeds quietly
against the second, and the listener keeps a usable request. Naming the host
makes that copy good only where it already arrived. It also means a reverse
proxy that rewrites `Host` will break every signature.

**`If-Match` on `/v1/meta`** — this carries the wrapped vault key, so a write
landing out of order reinstates an old wrapping, and after a master password
change that brings the old password back. The client cannot catch it on its own:
it watches for the sequence going backwards, and a stale header written late
arrives with the sequence going forwards like anything else.

**`If-Match` in the signature** — the header decides whether the write is
checked at all, so it cannot be left outside what is signed. Otherwise someone
on the path takes a request that is valid in every other respect and edits only
that header, turning a compare-and-swap into an unconditional overwrite without
holding any key. A negative value is refused outright for the same reason: below
the handler, negative means "not checking", which is legitimate only for the
first write to an empty store — reached by omitting the header, never by sending
a number.

A note on the nonce's lifetime, because getting it wrong is silent. A request is
good while `|now - ts| <= maxSkew`, which is a ten-minute span; a nonce is
recorded when it *arrives*. Remembering it for only `maxSkew` therefore leaves a
gap for any client whose clock runs ahead — the exact case the wide window
exists to tolerate — during which the nonce has been forgotten and the request
is still valid. They are kept for `2 * maxSkew`, which covers the whole window
from either direction.

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

## 5. Biometric unlock

**No component of ours.** The browser is asked for a key directly, through
WebAuthn's PRF extension: `navigator.credentials.create()` enrols a credential
on the platform authenticator, and `get()` evaluates PRF over a fixed salt to
return the same 32 bytes every time. Those bytes are the device secret. They
are never stored — they are re-derived from the hardware on each unlock — and
they wrap the vault key exactly as anything else would.

```
enrol   create({ rp: bencpass.invalid, prf: { eval: { first: SALT } } })
        → credentialId, and on some platforms the secret in the same breath
unlock  get({ allowCredentials: [credentialId], prf: { eval: { first: SALT } } })
        → the same 32 bytes, gated on user verification
```

Three constants are fixed for ever, and each for its own reason. The **salt**,
because changing it derives a different secret and every enrolled machine stops
opening its own vault. The **RP ID** (`bencpass.invalid`, an RFC 2606 reserved
name), because a credential created under one RP ID cannot be found under
another — and because a `moz-extension://` origin has no registrable domain, so
it has to be stated rather than inferred. The **AAD label**, which binds this
wrapping so it cannot be passed off as the password one.

What it costs: nothing. No native binary, no entitlement, no provisioning
profile, no annual renewal, no developer account, no hardware to buy.

| | |
|---|---|
| macOS | Touch ID. iCloud Keychain holds it as a passkey, so it is gated by a fingerprint per device and syncs across that Apple account — a boundary worth stating rather than assuming |
| Windows | Hello, via the TPM. Machine-bound, does not sync |
| Linux | nothing today: `enrol()` asks for a platform authenticator, and a plugged-in FIDO2 key is a roaming one. The desktop keyrings unlock with the login password, which would be a way into the vault *without* a password rather than a stronger one |

Enrolment costs two prompts on both platforms that have one. Firefox does not
return the PRF output from `create()`, so the secret is read back with a second
`get()`. The request at creation is left in place for the build where that
changes.

### The native host that was built first

`hosts/` holds a native messaging host — one JSON-over-stdio protocol and a
macOS implementation — that is **not used, not installed, and cannot be
reached**: the `nativeMessaging` permission has been removed from the manifest.

It was the original design, and the reason it is kept is that the negative
result cost a day to establish and is not written down anywhere else. A macOS
keychain item carrying a biometric access control needs a
`keychain-access-groups` entitlement that only Apple authorises; a self-signed
certificate embeds it happily and the kernel then refuses to run the binary.
Measured three ways on a runner rather than argued about — the table is in
`hosts/macos/README.md`, and the protocol it would have spoken is in
`hosts/PROTOCOL.md`.

Read that directory as a record of a route that closed, not as something to
install.


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
is narrowed to the two frames that must be page-embeddable — `overlay.html` and
`toast.html` — and nothing else.

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
5. **Biometric unlock.** WebAuthn PRF; no native component. (A host was built
   first and abandoned — the measurements are kept in `hosts/`.)
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

## 10. Failure mechanisms known and NOT closed

The point of this section is that a written limitation is not a surprise. Each
item is something the code does not defend against, or defends against only
partly. Format: what it is, what it costs, why it is not closed, and what would
close it. The sync engine's positive defences — per-record revisions, causal
merge, `guardRollback`, the per-record rollback report, the AAD-bound tombstone
bit, brittle-unlock tolerance, the locked-conflict refusal on every merge path,
and the flipped-flag reconciliation in `unlock`/`applyEnvelopes` — are covered
elsewhere and by the model test (`test/model.test.js`) and the deterministic
hostile tests (`test/hostile.test.js`). What follows is the residue.

**A dropped push the server claims it accepted.** A malicious or buggy server
can return `200` to a `PUT /v1/records` while storing nothing, advancing its
sequence so the next pull does not trip `guardRollback`. The write silently
evaporates. *Cost:* a record or edit the user made reaches neither the server
nor any other machine, while the origin machine believes it synced. *Why not
closed:* the client trusts the server's `200`; end-to-end encryption means the
server can always claim to hold ciphertext it discarded, and nothing it returns
is signed by anything the client could check. Over TLS the transport
authenticates the server, so the realistic actor is the server itself, which a
self-hosted deployment trusts. *What would close it:* read-back verification
(re-pull each pushed record and compare `ct`) at the cost of a round-trip per
sync, or server-signed write receipts. The hardened hostile server exercises
this (it drops ~15% of pushes while claiming success); invariants B and D still
hold because a dropped push is pure absence, which is why only A — deliberately
not required against such a server — is affected.

**A freshly joined machine has no rollback floor.** `guardRollback` and the
per-record rollback report both compare against state the machine accumulated —
`highestSeq` and `syncedRev`. A machine joining for the first time has neither,
so a hostile server can feed it an arbitrarily old but *authentic* version of a
record, including a pre-rotation password, and it is accepted as current because
there is nothing to compare it against. *Cost:* a new device can be seeded with
stale data; invariant B still holds (it never reverts a value *that machine*
moved past), and an honest server heals it on the next sync, but the join itself
is trust-on-first-use. *Why not closed:* causal ordering has no absolute floor
at join time — the first thing a machine sees is, by definition, its baseline.
*What would close it:* a signed, monotonic high-water-mark the joining machine
could trust — but the server holds no key and is the very party not trusted, so
this needs an out-of-band channel (e.g. the enrolment code carrying a sequence
floor).

**The server learns metadata it cannot read.** Per-record envelopes expose the
record count, each record's revision number, ciphertext sizes, and the timing
and per-device pattern of syncs. *Cost:* an observer of the store learns how
many credentials exist, how often each changes, and when each device is active —
never their contents. *Why not closed:* it is inherent in per-record sync, which
is the decision (§9) that stops a single blob eating a password. Hiding it would
need padding, constant-rate cover traffic, or a return to one blob, each worse.
*What would close it:* nothing worth the cost for a personal vault; documented
so the trade is explicit.

**The vault header is an offline-crackable target.** The server holds the KDF
parameters and the wrapped vault key, because a joining machine needs them.
*Cost:* anyone who takes the store can attack the master password offline, at
the speed the Argon2id parameters allow. *Why not closed:* a second machine
cannot bootstrap without the header. *What would close it:* nothing, short of
not supporting multi-machine sync; the mitigation is master-password entropy and
the KDF cost, both already in place and stated in the README.

**Selective denial of a record to a joining machine.** A hostile server can
serve a joining machine a `deleted`-flag-flipped or undecryptable envelope for a
specific record on every pull. The client correctly refuses it (`tampered`) or
files it as `damaged`, so the record never lands. *Cost:* availability — that
one record is withheld from that machine for as long as the server misbehaves.
Integrity and confidentiality are intact. *Why not closed:* the refusal is the
right call; adopting a contradictory or unreadable envelope would be worse.
Availability against a malicious server is out of scope. *What would close it:*
nothing at the client; an honest server never does this.

**No master-password change and no start-over.** The product cannot change the
master password or wipe-and-restart a vault in place (the manager's gate copy
now says so plainly, rather than pointing at a "freshly created vault" route
that was never built). *Cost:* a user who wants a new master password must
export, remove the extension's stored vault out of band, and set up fresh —
there is no guided path, and the recovery-code unlock deliberately does not
change the password. *Why not closed:* out of scope for this pass by decision.
*What would close it:* a password-change flow that re-derives the master key,
re-wraps the vault key, and republishes the header through the existing
`putMeta` compare-and-swap — the sequence-checked path that exists for exactly
this and is, today, the reason `putMeta` takes an `ifMatch`.

**Parked-conflict flood on a permanently locked vault.** A server that serves a
freshly sealed conflicting envelope on every poll defeats the `id:rev:nonce`
dedup mark by construction. A vault that never unlocks parks each one; the
`PARKED_MAX` (256) cap then discards the oldest. *Cost:* under a sustained
attack on a vault that is never unlocked, the oldest parked conflicts are
dropped before a person ever sees them. *Why not closed (fully):* the cap is the
only thing bounding disk and memory here; something must give. *Mitigation:* the
cap keeps the newest — most relevant — disagreements, and a single unlocked sync
forks and clears the queue. The `lockStreak` operation in the model exercises
the accumulation and dedup; the eviction itself is bounded by design.

### Test-coverage gaps (not source defects)

**Per-device equivocation is only approximated.** The model's hostile server has
no device identity, so a server that consistently lies to one device while
telling another the truth (a partition/equivocation attack) is exercised only as
per-call randomness, not as a stable per-device split. *What would close it:*
wrap each machine's client so requests carry a device tag and let the hostile
server branch on it.

**Device mint/revoke and the post-first-publish meta path are covered in Go, not
in the JS model.** The in-memory model server implements neither a device table
nor a second header publish (`shareHeader` writes only when the server holds no
header, and there is no password-change feature to call `putMeta` again). Those
paths are exercised by the Go server tests (`server/api_test.go`) and the
skip-gated integration tests in `test/sync.test.js`, not by the property model.
*What would close it:* a device table and a header-republish operation in the
model server.

**One merge guard rests on unit coverage alone.** The clause that stops a
higher-revision *live* envelope fast-forwarding over a local tombstone
(`(!l.deleted || r.deleted)` in `merge`) is not reached by the randomised
property runs — the delete-versus-edit-at-equal-revision race that would trigger
it is rare under the generator — but it is pinned by a deterministic test in
`test/merge.test.js`/`test/conflict.test.js`. Removing the clause fails those,
not the model. Noted so the reliance is explicit.
