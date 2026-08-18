# Does this machine's sensor answer to the browser?

One question, asked of the machine in front of you rather than of the
documentation: will this browser derive a stable 32-byte key from the
fingerprint reader already in this computer?

That is the whole of what BENCpass needs from the hardware. It is the WebAuthn
PRF extension, and whether it works is a fact about the browser *and* the
platform authenticator together — Firefox shipping it says nothing about
whether Windows Hello or a given security key will answer.

`../webauthn-probe.sh` runs this on macOS and Linux. Windows has no port,
because the page reports on screen and needs nothing but a local origin.

## Reading it

The line at the top is the verdict. The JSON underneath is where it came from:

```
platformAuthenticator: true              something built in was found
created.prfEnabled:    true              the new credential can derive
prfFirst:              "…  (32 bytes)"   what it derived
prfStable:             true              the same bytes twice — the one that matters
verdict:               "WORKS — …"
```

`prfStable: false` is the dangerous answer, not `prfEnabled: false`. A
credential that derives *something* each time but not the *same* thing would
enrol perfectly and then fail to unlock, which looks like a corrupt vault
rather than an unsupported browser. It is measured by evaluating twice and
comparing, which is why the test is worth more than the capability flags.

## Windows

There is no `.ps1` here on purpose: it could not be tested from the machine
that wrote it, and an untested launcher is a worse way to spend your afternoon
than three commands.

From the repository root, in PowerShell:

```powershell
$env:BIND = 'localhost'
node tools\serve.mjs $PWD.Path 8736
```

The path has to be absolute. `serve.mjs` refuses anything that does not resolve
back inside the root it was given, and a relative root fails that test against
itself — every request comes back `403 no`, which reads like a permissions
problem and is not one. (Measured, after documenting `.` here and trying it.)

Leave that running. In Zen or Firefox, open:

```
http://localhost:8736/tools/webauthn-probe/index.html
```

Then press the button and use Hello when it asks. The JSON appears on the page.

**`localhost`, never `127.0.0.1`.** Both are secure contexts, so WebAuthn is
available either way — but an IP address is not a registrable domain, and
WebAuthn will not accept an RP ID derived from one. The probe leaves `rp.id`
unset so the browser fills in the origin's domain, which only works when the
origin has one.

## What the answer changes

| | |
|---|---|
| `prfStable: true` | Hello can unlock the vault here. Enrol from Settings |
| `created.prfEnabled: false` | the browser or the authenticator will not do PRF. The master password is the way in, and BENCpass says so rather than offering a switch that fails |
| `platformAuthenticator: false` | nothing built in was found — no Hello enrolment on this PC, or it is switched off |

A `false` anywhere costs nothing but the fingerprint path: the master password
wrapping is untouched and opens the vault on any machine.

## When it fails with `UnknownError`

Firefox on Windows does not implement WebAuthn itself — it hands the request to
the operating system, and Windows answers a whole family of refusals with one
code that Firefox surfaces as:

```
UnknownError: The operation failed for an unknown transient reason
```

That names no ingredient. `variants.html`, next to this file, takes the request
apart and changes one thing at a time — plain, discoverable, PRF, then PRF and
discoverable together, which is what `enrol()` asks for. Whichever row is the
first to fail is the ingredient Windows objects to.

Serve it the same way and open:

```
http://localhost:8736/tools/webauthn-probe/variants.html
```

It raises a prompt per variant, and stops early at the first one that derives a
stable key. Successful variants leave a credential behind; they are harmless,
and Windows Settings → Accounts → Passkeys will remove anything named
"BENCpass probe".

Worth knowing before reading the result: `getClientCapabilities()` reports what
the *browser* supports, not what the authenticator behind it will actually do.
`extension:prf: true` alongside a failing `create()` is not a contradiction —
it is the browser saying yes and the platform saying no, which is precisely why
this page exists.

### What it found, Firefox 153 on Windows, 2026-08

**Windows Hello does PRF.** It derives a stable 32-byte key, discoverable or
not, and by either spelling — every variant above passes on the machine that
first reported it could not.

What it will not accept is being asked to *enable* PRF without *evaluating* it:

| Asked for at `create()` | Windows |
|---|---|
| `extensions: { prf: {} }` | `UnknownError: The operation failed for an unknown transient reason` |
| `extensions: { prf: { eval: { first: … } } }` | works |

One isolated `create()` is enough to see it, so it is not a matter of asking
too often, and "transient" is the error's word rather than a description — it
fails every time.

This cost an afternoon and two wrong conclusions, so it is worth being precise
about what misled: `residentKey` was blamed first and is innocent (Windows
grants a discoverable credential even when asked not to), then PRF itself was
blamed and is also innocent. The probe was asking the wrong question and
reporting the answer as a fact about the hardware.

`enrol()` in `../../src/ext/webauthn.js` has always asked with an eval, so the
extension never had this problem — only the page testing it did.

## The extension asks a narrower question

This page serves from `localhost` and lets the browser infer the RP ID. The
extension cannot: a `moz-extension://` origin has no registrable domain, so it
states `bencpass.invalid` outright — see the note on `RP_ID` in
`../../src/ext/webauthn.js`, and `../rpid-probe.sh` for which names Firefox
accepts from an extension page. So a good result here is necessary rather than
sufficient; the enrolment in Settings is the real test.
