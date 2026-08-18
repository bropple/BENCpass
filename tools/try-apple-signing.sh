#!/bin/sh
# Does an Apple-issued certificate authorise the keychain entitlement?
#
# A locally built host cannot store a hardware-protected secret: the keychain
# write needs `keychain-access-groups`, and an ad-hoc or self-signed certificate
# claiming it is killed on launch. Measured — see hosts/macos/README.md.
#
# An Apple *Development* certificate is a different thing, and a free Apple ID
# can create one. Whether it satisfies the entitlement is the question this
# answers. If it does, BENCpass gets the design it was meant to have, at no cost.
#
# This changes nothing permanently. On failure the ad-hoc signature is put back,
# so the host is left exactly as it was.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
binary="$root/build/hosts/bencpass-auth"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

if [ ! -x "$binary" ]; then
  echo "No host at $binary. Run hosts/install.sh first." >&2
  exit 1
fi

# ---- find a certificate ------------------------------------------------------

find_identity() {
  security find-identity -v -p codesigning 2>/dev/null |
    grep -E 'Apple Development|Mac Developer|Developer ID Application' | head -1 || true
}

identity=$(find_identity)

# A .p12 in cert/ is no use to codesign, which reads identities from a keychain
# rather than from a file. Offer to put it in one.
if [ -z "$identity" ]; then
  p12=""
  for f in "$root"/cert/*.p12 "$root"/cert/*.P12; do
    # AppleDouble sidecars share the extension and are not certificates.
    case ${f##*/} in ._*) continue ;; esac
    [ -f "$f" ] && p12="$f" && break
  done

  if [ -n "$p12" ]; then
    echo "found $p12, which is not in a keychain yet."
    echo "Importing it into your login keychain, for codesign only."
    printf 'Passphrase you set when exporting it: '
    stty -echo 2>/dev/null || true
    read -r p12pass
    stty echo 2>/dev/null || true
    echo

    if security import "$p12" -k "$HOME/Library/Keychains/login.keychain-db" \
         -P "$p12pass" -T /usr/bin/codesign 2>"$work/import.err"; then
      echo "imported."
      echo
    else
      echo "Could not import it:" >&2
      sed 's/^/  /' "$work/import.err" >&2
      echo >&2
      echo "A wrong passphrase reports as 'MAC verification failed', which does" >&2
      echo "not sound like a wrong passphrase but usually is." >&2
      exit 1
    fi
    p12pass=""
    identity=$(find_identity)
  fi
fi

if [ -z "$identity" ]; then
  cat >&2 <<'EOF'
No Apple code-signing certificate found on this Mac.

Nothing in cert/ either, or it did not import.

To make one — free, with the Apple ID you already have:

  Xcode -> Settings -> Accounts -> (+) -> Apple ID -> sign in
  select your account -> Manage Certificates -> (+) -> Apple Development

Then run this again.
EOF
  exit 1
fi

hash=$(echo "$identity" | awk '{print $2}')
name=$(echo "$identity" | sed 's/^.*"\(.*\)".*$/\1/')
echo "certificate: $name"

# The team identifier is the OU of the certificate subject, not the value in
# parentheses in its name — that one is the individual, and using it produces an
# access group the system will not accept.
team=$(security find-certificate -c "$name" -p 2>/dev/null |
  openssl x509 -noout -subject 2>/dev/null |
  tr ',/' '\n\n' | sed -n 's/^ *OU=//p' | head -1 || true)

if [ -z "$team" ]; then
  echo "Could not read a team identifier from that certificate." >&2
  exit 1
fi
echo "team:        $team"

# ---- sign with it ------------------------------------------------------------

cat > "$work/entitlements.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>com.apple.application-identifier</key>
  <string>$team.net.ropple.bencpass</string>
  <key>keychain-access-groups</key>
  <array>
    <string>$team.net.ropple.bencpass</string>
  </array>
</dict>
</plist>
EOF

cp "$binary" "$work/backup"
echo
echo "signing..."
if ! codesign --force --sign "$hash" --entitlements "$work/entitlements.plist" \
     --options runtime --timestamp=none "$binary" 2>"$work/err"; then
  echo "codesign refused:" >&2
  cat "$work/err" >&2
  cp "$work/backup" "$binary"
  exit 1
fi

# ---- ask it ------------------------------------------------------------------

msg='{"v":1,"op":"probe"}'
len=${#msg}
prefix=$(printf '\\%03o\\%03o\\%03o\\%03o' \
  $((len % 256)) $(((len / 256) % 256)) $(((len / 65536) % 256)) $(((len / 16777216) % 256)))

echo "asking the host what it can do now..."
echo
reply=$(printf "$prefix%s" "$msg" | "$binary" 2>/dev/null | tail -c +5 || true)

if [ -z "$reply" ]; then
  cat <<EOF
The host would not run at all — the kernel refused the entitlement, exactly as
it does for an ad-hoc signature.

That is the answer: an Apple Development certificate is not enough either, and
hardware-backed biometric unlock is out of reach without a paid Developer ID.
The ad-hoc signature has been put back; nothing has changed.
EOF
  cp "$work/backup" "$binary"
  codesign --force --sign - "$binary" >/dev/null 2>&1 || true
  exit 0
fi

echo "$reply" | sed -e 's/,"/,\n  "/g' -e 's/^{/{\n  /' -e 's/}$/\n}/'
echo

case $reply in
  *'"ok":true'*'-34018'*)
    echo "It runs, but the keychain still refuses: -34018 is still there."
    echo "Putting the ad-hoc signature back."
    cp "$work/backup" "$binary"
    codesign --force --sign - "$binary" >/dev/null 2>&1 || true
    ;;
  *'"ok":true'*)
    cat <<EOF
It runs, and nothing above says -34018.

If a "permanent" Secure Enclave variant reports ok, this works and BENCpass can
have the design it was meant to have. Send me the output and I will wire this
signature into hosts/install.sh so every rebuild uses it.

The signature has been left in place.
EOF
    ;;
  *)
    echo "Unexpected reply; ad-hoc signature restored."
    cp "$work/backup" "$binary"
    codesign --force --sign - "$binary" >/dev/null 2>&1 || true
    ;;
esac
