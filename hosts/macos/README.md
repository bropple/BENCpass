# The macOS host

Touch ID in front of one random string. It never sees the master password, the
vault key, or a record — see `../PROTOCOL.md`.

## Why the secret is not in the keychain

The obvious design is a keychain item carrying a biometric `SecAccessControl`.
It does not work for a locally built program, and the reason is not something
that can be read out of the documentation — it was measured on a runner, three
ways, in `.github/workflows/hosts.yml`:

| Signature | Result |
|---|---|
| ad-hoc, no entitlements | runs; `SecItemAdd` refused `-34018` on **both** keychains |
| ad-hoc + `keychain-access-groups` | `Killed: 9` — refused at launch |
| trusted self-signed certificate + `keychain-access-groups` | `Killed: 9` — refused at launch |

`-34018` is `errSecMissingEntitlement`. The entitlement it wants is authorised
by Apple and by nobody else: a certificate you make yourself embeds it happily
and the kernel then declines to run the program at all. Signing with an Apple
Developer identity would work, and would mean nobody could build this from
source without an account.

## What it does instead

The same probe that closed that door found the way through. Creating a Secure
Enclave key with `.biometryCurrentSet`, from the same unentitled ad-hoc binary,
is **not** refused for want of an entitlement — on a runner it fails with
`Failed to get bio catacomb UUID`, which is LocalAuthentication saying the
machine has no fingerprint enrolled. True of a runner. Not true of a laptop.

So the shape is inverted:

- a key is generated **inside** the Secure Enclave, its use gated by a
  fingerprint;
- the device secret is sealed to that key's public half and written to
  `~/Library/Application Support/BENCpass/<id>.sealed`, mode 0600.

The file is worthless without the enclave. The enclave will not act without the
fingerprint. The private key has never existed outside the hardware and cannot
be exported.

Every property the keychain approach was chosen for survives — it cannot leave
this Mac, changing the enrolled fingerprints destroys the key, and a copy of the
file opens nothing anywhere. One improves: the secret is in no keychain at all,
so no other program can be prompted into handing it over.

Enrolment raises no prompt, because sealing uses the public key, which the
enclave hands out freely. Only reading it back costs a fingerprint.

## The entitlements file

`bencpass-auth.entitlements` is kept for the experiment above and is **not** used
to sign the installed binary — signing with it would make the host unrunnable.

It carries no comments on purpose. XML forbids `--` inside a comment and the
entitlements parser enforces it, so a comment mentioning `codesign --sign` fails
with `AMFIUnserializeXML: syntax error` and the signature is then written with no
entitlements at all, silently.

## Diagnosing

```
{"v":1,"op":"probe"}
```

Attempts the keychain write against both keychains and a Secure Enclave key
creation, and reports every status without storing anything. `SecItemAdd` does
not prompt — the biometric constraint is evaluated on read — so this answers on
a machine with no fingerprint reader.
