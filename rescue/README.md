# BENCpass Rescue

Opens a BENCpass vault without a browser.

This is the program for the day the extension cannot help: a profile that will
not load, a Firefox that will not install, a laptop that is gone. Given the
vault and either the master password or the printed recovery code, it lists
what is inside and writes it back out in a form something else can read.

It never writes to the file you give it, and it never touches the network.

<p align="center">
  <img src="../assets/brand/benco-gon-medic.svg" width="120" alt="P. Gon with a medical kit">
</p>

---

## What it opens

**An encrypted backup**, from BENCpass → Settings → Your data → Encrypted
backup. This is the one to keep. It is the whole vault, still sealed, so it is
safe on a USB stick or a cloud drive — and it is the only practical way to get
the vault out of `browser.storage.local`, which lives inside Firefox's IndexedDB
and is not something anyone extracts by hand in a hurry.

**A sync server's `store.json`**, or the data directory holding it. If you ran
the server, this is a complete copy of the vault that survives the loss of every
machine. Point the tool at the dataset and it finds the file.

Both are opened with the master password, or with the recovery code if you
enrolled one.

**Not the fingerprint.** That secret lives inside the authenticator and is only
released to a browser making a WebAuthn call. Nothing outside one can reproduce
it, and the tool says so rather than leaving you wondering.

---

## Getting it

Binaries for macOS, Windows and Linux are attached to every
[release](https://github.com/bropple/BENCpass/releases), beside the signed
`.xpi`. There is nothing to install: one file, no runtime, no dependencies.

Keep a copy with your backup. The day you need it is a bad day to be
downloading things.

### Check it before you trust it

This program is one you type your master password into, so it is worth thirty
seconds. The `.xpi` beside it carries Mozilla's signature; these do not, so they
carry two other things instead.

```sh
sha256sum -c SHA256SUMS                       # matches the release page
gh attestation verify bencpass-rescue-Linux.tar.gz --repo bropple/BENCpass
```

The second is the stronger one. A checksum sitting on the same page as the file
only proves they agree; the attestation ties the archive to the workflow run and
the commit that built it, which is what would catch a release asset being
swapped by anyone who could edit the release.

**On macOS** an unsigned binary from a downloaded archive is refused by
Gatekeeper — "cannot be opened because the developer cannot be verified". The
checksum does not change that; right-click → Open, or
`xattr -d com.apple.quarantine bencpass-rescue`, until these are notarized.

---

## Using it

Run it with no arguments and it asks for a file. Or drop a file onto the window.

It also works with no window at all, which is what a NAS holding the
`store.json` can actually run:

```sh
bencpass-rescue -info    backup.json          # what is this file? no password needed
bencpass-rescue -list    backup.json          # what is in it
bencpass-rescue -show    github backup.json   # one record, secrets included
bencpass-rescue -export  out.json backup.json # all of it, as .json or .csv
bencpass-rescue -recovery -list backup.json   # unlock with the printed code
```

The secret is read from the terminal without echoing, or from standard input
when piped:

```sh
printf '%s' "$PASSWORD" | bencpass-rescue -list backup.json
```

Exports are written `0600` and refuse to overwrite an existing file. `.json`
keeps everything; `.csv` is logins only, in the shape other managers read, and
both import straight back into BENCpass.

`-list` does not print passwords. `-show` does, and says first that a terminal
keeps scrollback.

---

## Building it

```sh
cd rescue
go build -o build/bencpass-rescue .
go test ./...
```

Linux needs a windowing stack to compile against: `libgl1-mesa-dev` and
`xorg-dev` on Debian and Ubuntu. macOS and Windows need nothing extra.

The tests need `node` on PATH, because they are cross-language on purpose — see
below. Without it the interesting ones skip.

---

## Why Go, and why not raylib

The other BENC desktop apps are raylib, and
`style/benco-desktop-app-conventions.md` says anything after them should be too.
This one is not, deliberately.

It needs Argon2id and AES-256-GCM, and writing that in C for a program whose
entire job is reading password vaults is a worse trade than departing from the
toolkit convention. Go has AES-GCM in the standard library and Argon2id in
`golang.org/x/crypto`, produces one static binary per platform with no runtime,
and is memory-safe while parsing a `store.json` that may have come off a
networked machine.

The visual conventions are kept. Every colour is copied from `src/ui/style.css`
rather than chosen, and the fonts are the two the extension ships. It should
look like the manager, because it is doing the manager's job.

---

## Two implementations of one format

The vault format now has two implementations: `src/core/` in JavaScript, and
`rescue/internal/vault/` in Go. Two implementations drift — quietly, and in the
direction nobody is looking, because the one that has to work is the one nobody
exercises until it matters.

So the Go tests do not compare against constants a Go programmer typed:

- `internal/vault/testdata/` is **sealed by the real JavaScript core**, and
  `expected.json` is what that core says is inside it. Argon2's parameters, the
  AAD strings, the base64 and the record shape are pinned by construction.
- the export round trip is **read back by the extension's own importer**, run
  under node, so a divergence in the envelope or the CSV quoting fails a test
  rather than a person.
- CI regenerates the fixtures and fails if they moved, which is what catches
  the format changing on one side only.

Regenerate them after any change to the vault format:

```sh
node rescue/internal/vault/testdata/gen.mjs
```

---

## What it will not do

It does not edit, and it does not write to your vault. If it could, then the
program you reach for when everything is broken would also be the program that
can finish the job.

It cannot recover a vault whose master password and recovery code are both
gone. There is no back door, and adding one would make the recovery code
pointless.
