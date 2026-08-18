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
    echo "No signing identity in your keychain, but there is $p12."
    echo
    echo "The passphrase below is the one set when that file was *exported* —"
    echo "not your Apple ID password, which is never involved here. If you did"
    echo "not set one, press Enter."
    echo
    printf 'Export passphrase (or Enter for none): '
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
      echo "'MAC verification failed' means the passphrase was wrong, however" >&2
      echo "little it sounds like it." >&2
      echo >&2
      echo "If Xcode made this certificate, the private key is probably already" >&2
      echo "in your login keychain and this file is not needed. Check with:" >&2
      echo "  security find-identity -v -p codesigning" >&2
      echo >&2
      echo "Nothing listed there means the key is missing rather than the" >&2
      echo "certificate — a .cer on its own cannot sign anything." >&2
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

# ---- try each entitlement, separately ---------------------------------------
#
# Not one bundle. `com.apple.application-identifier` is a *restricted*
# entitlement — it has to be backed by a provisioning profile, and AMFI kills
# anything claiming it without one. Bundling it with the entitlement actually
# wanted meant a rejection could not be attributed to either, and the first run
# of this script did exactly that.

cp "$binary" "$work/backup"
restore() {
  cp "$work/backup" "$binary"
  codesign --force --sign - "$binary" >/dev/null 2>&1 || true
}

msg='{"v":1,"op":"probe"}'
len=${#msg}
prefix=$(printf '\\%03o\\%03o\\%03o\\%03o' \
  $((len % 256)) $(((len / 256) % 256)) $(((len / 65536) % 256)) $(((len / 16777216) % 256)))

ask() { printf "$prefix%s" "$msg" | "$binary" 2>/dev/null | tail -c +5 || true; }

# name|entitlements-body. An empty body means sign with the certificate and no
# entitlements at all, which separates "the certificate is fine" from "the
# entitlement is refused".
variants="none|
group-with-team|<key>keychain-access-groups</key><array><string>$team.net.ropple.bencpass</string></array>
group-team-only|<key>keychain-access-groups</key><array><string>$team</string></array>
group-plus-appid|<key>keychain-access-groups</key><array><string>$team.net.ropple.bencpass</string></array><key>com.apple.application-identifier</key><string>$team.net.ropple.bencpass</string>"

winner=""
echo "$variants" | while IFS='|' read -r vname body; do
  [ -n "$vname" ] || continue

  cp "$work/backup" "$binary"
  if [ -z "$body" ]; then
    codesign --force --sign "$hash" "$binary" >/dev/null 2>&1 || true
  else
    cat > "$work/e.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>$body</dict>
</plist>
PLIST
    codesign --force --sign "$hash" --entitlements "$work/e.plist" "$binary" \
      >/dev/null 2>&1 || { echo "  $vname: codesign refused it"; continue; }
  fi

  reply=$(ask)
  if [ -z "$reply" ]; then
    echo "  $vname: killed on launch"
    continue
  fi

  case $reply in
    *'-34018'*) echo "  $vname: runs, keychain still refuses (-34018)" ;;
    *) echo "  $vname: RUNS, and no -34018 — this is the one"
       echo "$vname" > "$work/winner"
       echo "$reply" > "$work/winning-reply" ;;
  esac
done

echo
if [ -f "$work/winner" ]; then
  echo "A signature that works: $(cat "$work/winner")"
  echo
  sed -e 's/,"/,\n  "/g' -e 's/^{/{\n  /' -e 's/}$/\n}/' "$work/winning-reply"
  echo
  echo "Send me this and I will wire it into hosts/install.sh."
  echo "The host has been left signed with the last variant tried; rerun"
  echo "hosts/install.sh to get back to a known state."
else
  cat <<'EOF'
None of them ran with the entitlement, and signing with the certificate alone
changes nothing about the keychain.

That points at a provisioning profile rather than at the certificate tier — the
entitlement has to be authorised by a profile embedded in the binary, and a
paid account is not the only way to get one. Xcode can generate a development
profile for a free account.

So: do not pay for this yet. The next thing to try is a profile, not a receipt.
EOF
  restore
fi
