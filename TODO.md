# TODO

Things worth doing, none of them urgent enough to have held a release. Each says
why it matters and what "done" looks like, so a future session does not have to
reconstruct the reasoning.

For failure mechanisms this code knowingly does not defend against — a different
kind of list — see ARCHITECTURE.md §10. This file is for work; that one is for
limits.

---

## Import adds; it never merges

`Vault.importRecords` (src/core/vault.js) mints a fresh uuid for every row and
writes it as a new record. It never looks at what is already in the vault.

So importing the same Firefox export on two machines produces two independent
records per login, with different ids — and sync treats different ids as
different records, so both propagate to both machines. Every login ends up
twice, and no conflict is raised, because from the vault's point of view nothing
conflicted. The workaround today is to import once, on one machine, and let sync
carry the rest; nothing in the interface says so.

**Done looks like:** an import that offers to merge a row into an existing entry
matched on registrable domain and username, rather than always adding. Reuse
`captureTarget`/`belongsOnlyTo` in src/core/match.js — the capture path already
solves exactly this problem and refuses to overwrite an entry that names other
sites. Duplicates should be the user's decision, not the default.

## Import throws away the timestamps the file carried

`fromCsv`/`fromJson` (src/core/transfer.js) build every record through
`newRecord`, which stamps `created`, `updated` and `passwordChanged` with the
import time. Firefox's CSV carries `timeCreated`, `timeLastUsed` and
`timePasswordChanged`, and all three are dropped on the floor.

That is worse than untidy. "Which copy is the newest" is the question this
program exists to answer, and importing flattens the only evidence: two records
imported from different machines both claim to have been changed today.

**Done looks like:** parse the timestamp columns where the source has them, and
let a record arrive with a past `passwordChanged`. `normalise` in
src/core/model.js already clamps implausible timestamps, so the guard is
written; it is the parser that never supplies them. Note the JSON path is
partly here already — history now survives a round trip — so this is mostly CSV.

## The rescue tool does not show password history

`-show` prints title, username, password, totp and notes (rescue/cli.go:188).
The JSON export keeps history, and the manager can display it, but the tool
somebody reaches for when the browser will not start cannot show the older
password that might be the one they need.

**Done looks like:** `-show` prints previous passwords with their dates, behind
the same "this prints secrets to a terminal" warning as the current one.

## Biometrics on Linux: platform-only, by pin

`src/ext/webauthn.js:116` pins `authenticatorAttachment: 'platform'`, and
`available()` gates on `isUserVerifyingPlatformAuthenticatorAvailable()`.
Firefox on Linux has no platform authenticator, so the feature is simply absent
there. The copy was corrected to stop promising security keys; the capability
was not added.

**Done looks like:** either roaming authenticators (a plugged-in FIDO2 key) are
supported and the copy says so again, or a decision is recorded here that they
are deliberately out of scope. Note the awkward part: availability cannot be
probed without prompting, so the interface has to offer something it may not be
able to deliver.

## The TrueNAS app icon is a placeholder

The server's own status page serves P. Gon as its favicon (`/favicon.svg`), but
the TrueNAS Apps list shows a generic icon, because custom apps installed via
YAML take their icon from TrueNAS's catalog metadata rather than from the image
or the compose file.

**Done looks like:** either a note in TRUENAS-DEPLOY.md pointing at
`http://<nas>:8788/favicon.svg` for the icon field where the UI offers one, or a
PNG endpoint beside the SVG for UIs that will not render SVG. The rescue tool
already commits a 512px render to work from.
