# Why there is an entitlements file

A keychain item carrying a biometric `SecAccessControl` is refused with
`errSecMissingEntitlement` (-34018) unless the signature on the binary claims a
keychain access group. That is a fact about the signature rather than about the
code, which is why it cannot be fixed by writing the Swift differently — and why
two attempts at reasoning it out from the documentation were both wrong.

Measured on a runner, with no fingerprint reader, because `SecItemAdd` does not
prompt — the biometric constraint is evaluated when the item is *read*. See the
keychain experiment in `.github/workflows/hosts.yml` for what each signature
gets.

The file carries no comments on purpose. XML forbids `--` inside a comment, and
the entitlements parser is strict about it: a comment mentioning `codesign
--sign` fails to parse with `AMFIUnserializeXML: syntax error`, and the
signature is then written without any entitlements at all.
