# TODO

Things worth doing, none of them urgent enough to have held a release. Each says
why it matters and what "done" looks like, so a future session does not have to
reconstruct the reasoning.

For failure mechanisms this code knowingly does not defend against — a different
kind of list — see ARCHITECTURE.md §10. This file is for work; that one is for
limits.

---

## Biometrics on Linux: roaming authenticators are out of scope

Decided 2026-08, recorded in full beside the pin it concerns
(`authenticatorSelection` in src/ext/webauthn.js). The short form: availability
of a plugged-in FIDO2 key cannot be probed without prompting, so the interface
would have to offer an unlock it cannot promise; PRF over a hardware key on
Firefox's Linux CTAP2 stack has never been measured here, and everything in
that file was measured before it shipped; and nothing is lost that the design
does not cover — the master password works everywhere and the recovery code is
the way back. Revisit only with a real key in hand, by extending
tools/webauthn-probe.sh first.

## Print on the recovery sheet: the tab path is assumed, not hand-verified

The sidebar case is fixed: `window.print()` from a sidebar panel does nothing
at all, so the button there now says so and points at Copy and the code on
screen instead of failing silently (src/ui/manager.js, the kit-print handler —
"do I have a tab" is the test, via `tabs.getCurrent()`). In a tab the call is
the browser's own print dialog and the `@media print` block strips the page to
the code; that is standard behaviour and there is no reason to expect it
broken, but nobody has pressed it in a real tab since the change. Next time a
recovery sheet is on screen in a tab, press Print once and delete this entry.

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

## The revoke button is offered when it cannot work

With one machine enrolled, the server refuses (`ErrLastDevice`,
server/store.go:386) and the manager already has good copy explaining why. But
the button is enabled, so the only way to find out is to press it. A control
that can only fail should say so before it is pressed, not after — disable it
with the reason visible.

(The other device gap that used to live here — no way in when every machine is
lost — is closed: `bencpass-rescue -devices` / `-forget` removes dead devices
from a server store offline, backup first, so the server prints a fresh
bootstrap code again.)

## tools/testpage still lacks the appliance-settings shape

The "Save 14 for 10.0.0.214?" capture is fixed — bare-digit usernames are
refused at capture time (`plausibleUsername` in src/core/fields.js, applied in
background.js's handleCapture), and the observed shape is pinned in
test/fields.test.js and test/background.test.js, including the interaction
with generated passwords. What remains is the live-browser half: a
"dynamically rendered form with numeric settings beside a password field" case
in tools/testpage, which describes most appliance and self-hosting UIs and is
worth having the selftest drive for real. It was not added because tools/ was
owned by other work at the time; add the case and a selftest check that no
save offer appears for it.
## Observed, not yet diagnosed

Field reports from real use that are not actionable yet: no reproduction, no
established cause, and sometimes no certainty there is a bug at all. They sit
apart from the list above so that list stays honest about its own size.
Anything here needs a diagnosis before it needs a fix.

**One account, two valid identifiers.** American Airlines accepts either an
AAdvantage number or an email address to sign in — one account, two things that
work in the username box. A record holds one `username`, so today that means
either two records for one account or the second identifier buried in notes
where nothing can fill it. Neither is right, and the pattern is not unique to
AA: airlines, banks, insurers and utilities routinely accept a member or
account number alongside an email.

Not obviously a feature request yet, because the shape matters more than the
storage. A second username field is easy and probably wrong — it invites "which
one does this site want", which is the question the person came here to stop
asking. Worth thinking about whether the menu simply offers both for the same
entry, and what that does to matching, to capture (a sign-in with the number
must not create a second record), and to the conflict machinery.

(An earlier note here reported AA's login not autofilling. That turned out to be
a password *reset* page — four fields, only the password anchored, which is
correct: the name and email fields are not login fields, and the password field
is exactly where a generated password belongs. No bug; removed rather than left
to look like one.)
