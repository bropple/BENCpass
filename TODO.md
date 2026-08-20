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

## Print on the recovery sheet does nothing

Reported from real use. The button is wired — `$('kit-print')` calls
`window.print()` (src/ui/manager.js:613) — and there is a `@media print` block
in src/ui/style.css that strips the page to the code and its date. So this is
not a missing handler.

**Confirmed: it was pressed in the sidebar.** The manager runs both as a tab and
in the sidebar, and `window.print()` from a sidebar panel does nothing at all —
no dialog, no error. Whether it also fails in a tab is not known; that is the
first thing to check, because it decides whether this is "make the sidebar do
something else" or "the call is wrong everywhere".

Worth taking seriously despite being one button: the recovery code is shown
once and never stored, and printing it is the path the interface recommends. A
person who presses Print, sees nothing happen, and closes the sheet has lost
the code.

**Done looks like:** check the tab case, then either make it work in the sidebar
or say so there and offer something that does —
opening the sheet in a tab for printing, or a copy-to-clipboard beside it.
Whatever it becomes, pressing it must visibly do something, because the failure
mode is silent and the cost is the whole recovery path.

**Workaround meanwhile:** the code is on screen — write it down, or open the
manager in a tab and use the browser's own print.

## No way to tell the save prompt "never for this site"

The toast offers Save and Dismiss. Dismiss is for this once — the next sign-in
on the same site asks again. There is no way to say "stop asking about this
one", which every other password manager has, and which matters most on the
sites you sign into constantly and will never want stored: a bank that you
deliberately keep out of a vault, a shared account, a throwaway login, a local
development site that generates a new username every run.

**Done looks like:** a third choice on the toast that adds the site to a list,
and a visible, editable list of those sites in Settings so a decision made in a
hurry can be undone. Store it beside the settings rather than in the vault: it
is a preference about a site, not a secret, and keeping it out of the vault
means it does not sync a personal choice to every machine unless that is
deliberately wanted — decide which, and say why in the code.

**The interaction to be careful about.** Generating a password now saves it
immediately, before it reaches the page, precisely so it cannot be lost
(src/core/provisional.js). "Never for this site" must not silently discard a
password the person just generated and used — that would recreate the exact
failure the provisional entry was built to prevent. Either the block applies
only to captures of passwords typed by hand, or generating on a blocked site
warns plainly that it will not be kept. The first is probably right; the second
is at least honest. What must not happen is a generated password vanishing
because of a preference set weeks earlier.

## Format 2 is load-bearing now, and there is no migration path

`Vault.load` refuses any vault whose format is not the current one
(src/core/vault.js:197). It does not migrate; it says the vault "was written by
an older BENCpass, and its weaker sealing is refused rather than read".

That was the right call when it was made. The format-1 to format-2 change
happened while nothing was installed anywhere, so there were no vaults to strand
and a reader that accepted both would have been a downgrade path — an attacker
who could present an envelope claiming the older format would get the weaker
authentication back.

**That justification has expired.** There are real vaults in format 2 now, with
real passwords in them. The next format change cannot simply refuse what came
before: it would strand the vault it was meant to protect, and the person
holding it would have a master password that opens nothing.

**So, before any future change to the envelope or header format:** write the
migration first, not the refusal. Read the old format, re-seal into the new one,
persist, and only then start refusing what is genuinely older than anything that
can exist. Test it against a real vault of the previous format — commit a
fixture of one, since after the change there is no other way to produce it.

Note what makes this awkward and why it needs thought rather than a flag: a
reader that accepts two formats is a downgrade path for as long as it exists.
The answer is probably to migrate on load and write only the new format, so the
old reader exists but its output never survives a save — but that is a design
decision to make deliberately, with the security consequence stated, rather than
discovered halfway through an upgrade.

Related, and the reason this matters today rather than eventually: updating the
extension keeps the vault (same extension id, same `storage.local`), but
UNINSTALLING deletes it. Anyone treating uninstall-then-install as an upgrade
loses everything. That belongs in the README where a person will meet it.

## Two gaps around devices

**The revoke button is offered when it cannot work.** With one machine enrolled,
the server refuses (`ErrLastDevice`, server/store.go:386) and the manager already
has good copy explaining why. But the button is enabled, so the only way to find
out is to press it. A control that can only fail should say so before it is
pressed, not after — disable it with the reason visible.

**No way in when no usable device is left.** Every device operation — list,
rename, revoke, mint — is signed with an enrolled device's key, which is right:
the server holds no key and should not be an admin surface. But it means that if
every machine is lost or wiped, nothing can enrol a new one: minting needs an
enrolled machine to ask, and the bootstrap code is printed only while no device
is enrolled, so the dead machines hold the door shut.

The data is never at risk — `bencpass-rescue` reads `store.json` directly — and
the procedure is now documented in TRUENAS-DEPLOY.md ("If you lose every machine
but still have the server"): stop the app, empty `devices` in `store.json`,
restart, take the fresh bootstrap code. But that is hand-editing JSON on a NAS,
which is a poor thing to ask of someone on the worst day of their week.

**Done looks like:** an offline subcommand on the rescue tool — it already reads
a server store, is read-only today, and is the thing a person already has for
this kind of day. Something like `bencpass-rescue -devices <store.json>` to list
them and `-forget <id>` to drop one, operating on the file with the server
stopped. Deliberately NOT a new endpoint on the running server: the whole point
is that it holds no key and answers only signed requests, and an admin path that
did not need one would undo that.

## No Test button on the join gate

The endpoint **Test** lives in Settings → Sync, which needs an unlocked vault.
A machine that is joining has no vault yet, so the one moment a person most
wants to check the address — typing it for the first time, on a second machine,
with a code that expires in thirty minutes — is the moment they cannot.

Get it wrong and the failure arrives after the master password and the code have
been entered, as a join error rather than "that address is not answering". The
code may also have been spent by then, which turns a typo into a trip back to
the first machine to mint another.

**Done looks like:** the same Test beside the server field on the join gate,
doing what it does in Settings — an unauthenticated GET of `/v1/health`,
reporting the protocol mismatch case by name. It needs no key and no vault, so
there is nothing stopping it existing there; it simply was not built.

Worth doing at the same time: the gate's server field could say what it will and
will not take (a LAN address, `.local`, or an https Tailscale name — not a
Tailscale IP over plain http), which is the other thing a person only discovers
by being refused.

## A numeric field was captured as a username

Seen in real use (screenshots/Screenshot 2026-08-20 000752.png): the save toast
offered *"Save 14 for 10.0.0.214?"* on a LAN device's admin page. `14` is not a
username — something numeric on that page was classified as one, and a password
field was matched alongside it well enough to make an offer.

The capture side is more forgiving than the fill side, and deliberately: a
missed save loses a password the person just chose, while a wrong offer costs a
click on Not now. But an offer with obvious rubbish in it teaches people to
dismiss the toast without reading it, and a toast nobody reads is worse than one
that appears less often — the day it is offering something real is the day the
habit costs them.

**The page was the TrueNAS SCALE web UI**, which narrows it usefully. That is an
Angular single-page app: forms are built at runtime, fields frequently carry no
`autocomplete` attribute worth reading, and its app-install and service pages
routinely put numeric settings — ports, counts, sizes — in the same form as a
password. `14` is far more likely one of those than anything a person would
call a username.

It is also a page shape worth being able to test against, because "dynamically
rendered form with numeric settings beside a password field" describes most
appliance and self-hosting UIs, not just this one. tools/testpage is where that
case belongs.

**Still not known:** which specific field it was. Establishing that decides
whether the fix belongs in the classifier or in what counts as a capturable
pair.

**Done looks like:** a capture is not offered when the username-shaped value
cannot plausibly be one — bare digits are the clear case, and there may be
others — while still capturing a genuinely empty username, which is legitimate
on a second-step sign-in and already handled. Whatever rule is chosen, the
existing tests in test/fields.test.js and tools/testpage are where it gets
pinned; add the observed shape as a case.

Related: this is the strongest argument for the "never for this site" option
above. A LAN appliance's admin page is exactly the thing somebody wants silenced
for good, and no classifier will ever get every such page right.
