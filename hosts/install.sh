#!/bin/sh
# Build and register the BENCpass native host.
#
#   hosts/install.sh            build for this platform and install the manifest
#   hosts/install.sh uninstall  remove the manifest and forget the secret
#
# The host is what puts Touch ID in front of the vault. Without it BENCpass
# works exactly as before, asking for the master password — so this is optional,
# and removing it takes nothing with it but the shortcut.
#
# Registration is a JSON manifest in a directory the browser reads at startup.
# `allowed_extensions` in that manifest is the access control: only BENCpass can
# start the program, so no page and no other add-on can reach the keystore
# through it.
set -eu

name="net.ropple.bencpass.auth"
extension_id="bencpass@ropple.net"
root=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$root/.." && pwd)

case $(uname -s) in
  Darwin)
    platform=macos
    # Firefox and Zen both read the Mozilla directory; Zen is a Firefox fork and
    # has not moved it.
    manifest_dir="$HOME/Library/Application Support/Mozilla/NativeMessagingHosts"
    binary="$repo/build/hosts/bencpass-auth"
    ;;
  Linux)
    platform=linux
    manifest_dir="$HOME/.mozilla/native-messaging-hosts"
    binary="$repo/build/hosts/bencpass-auth"
    ;;
  *)
    echo "No host for $(uname -s). Windows uses hosts\\windows\\install.ps1." >&2
    exit 1
    ;;
esac

manifest="$manifest_dir/$name.json"

if [ "${1:-}" = "uninstall" ]; then
  rm -f "$manifest"
  echo "removed $manifest"
  if [ "$platform" = macos ]; then
    echo "The secret itself is in the login keychain as 'BENCpass device secret'."
    echo "Turning biometric unlock off in BENCpass removes it; this script does not,"
    echo "because a manifest can be reinstalled and a deleted secret cannot."
  fi
  exit 0
fi

# ---- build -----------------------------------------------------------------

case $platform in
  macos)
    if ! command -v swiftc >/dev/null 2>&1; then
      echo "swiftc not found. Install the Xcode command line tools:" >&2
      echo "  xcode-select --install" >&2
      exit 1
    fi
    echo "building $binary"
    mkdir -p "$(dirname "$binary")"
    swiftc -O -o "$binary" "$root/macos/main.swift"

    # Ad-hoc signing. Not for distribution — it is what makes macOS attribute
    # the Touch ID prompt to a stable identity instead of treating each rebuild
    # as a new program, which would otherwise invalidate the stored secret.
    if command -v codesign >/dev/null 2>&1; then
      codesign --force --sign - "$binary" >/dev/null 2>&1 ||
        echo "warning: could not ad-hoc sign; Touch ID may re-prompt after a rebuild" >&2
    fi
    ;;
  linux)
    echo "No biometric host for Linux."
    echo
    echo "There is no equivalent of Touch ID or Hello to put in front of the"
    echo "secret here: the desktop keyrings unlock with your login password,"
    echo "which would make this a way to open the vault *without* a password"
    echo "rather than a stronger one. BENCpass asks for the master password on"
    echo "Linux, which is the honest answer."
    exit 0
    ;;
esac

# ---- register ---------------------------------------------------------------

mkdir -p "$manifest_dir"
cat > "$manifest" <<EOF
{
  "name": "$name",
  "description": "BENCpass biometric unlock",
  "path": "$binary",
  "type": "stdio",
  "allowed_extensions": ["$extension_id"]
}
EOF

echo "installed $manifest"
echo
echo "Restart the browser, then turn on biometric unlock in BENCpass."
echo "You will be asked for your master password once, to wrap the vault key"
echo "for the keystore — see the second-wrapping notes in src/core/vault.js."
