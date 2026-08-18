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

# Where the browser looks for a manifest is the vendor directory, resolved from
# `XREUserNativeManifests` — see NativeManifests.sys.mjs, which asks the
# directory service rather than hard-coding a path. Zen is a Firefox fork and
# its libxul carries the Mozilla vendor strings and no Zen ones, so it reads
# Mozilla's directory.
#
# Every plausible location is written anyway. The alternative is a manifest in
# the wrong place, which fails as the feature simply not appearing — no error,
# nothing in a log, and no way to tell it apart from a browser that has not been
# restarted. A stray JSON file in a directory nothing reads costs nothing.
case $(uname -s) in
  Darwin)
    platform=macos
    manifest_dirs="$HOME/Library/Application Support/Mozilla/NativeMessagingHosts
$HOME/Library/Application Support/Zen/NativeMessagingHosts
$HOME/Library/Application Support/zen/NativeMessagingHosts"
    ;;
  Linux)
    platform=linux
    manifest_dirs="$HOME/.mozilla/native-messaging-hosts
$HOME/.zen/native-messaging-hosts"
    ;;
  *)
    echo "No host for $(uname -s). Windows uses hosts\\windows\\install.ps1." >&2
    exit 1
    ;;
esac
binary="$repo/build/hosts/bencpass-auth"

if [ "${1:-}" = "uninstall" ]; then
  echo "$manifest_dirs" | while IFS= read -r dir; do
    [ -f "$dir/$name.json" ] || continue
    rm -f "$dir/$name.json"
    echo "removed $dir/$name.json"
  done
  if [ "$platform" = macos ]; then
    echo
    echo "The sealed secret and its Secure Enclave key are left alone. Turning"
    echo "biometric unlock off in BENCpass removes both; this script does not,"
    echo "because a manifest can be reinstalled and an enclave key cannot."
    echo "  $HOME/Library/Application Support/BENCpass/"
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
    # A binary from before the move to build/ may still be sitting where the
    # first version of this script put it, and a manifest from that era still
    # points at it. Pulling new source does not touch either, so the browser
    # goes on running a host whose design was replaced — which fails with an
    # error message from that design and reads exactly like the current one
    # being broken.
    for legacy in "$root/macos/bencpass-auth" "$root/linux/bencpass-auth"; do
      if [ -f "$legacy" ]; then
        rm -f "$legacy"
        echo "removed a host left over from an older layout: $legacy"
      fi
    done

    cat <<'NOTE'
Note: biometric unlock is parked on macOS, not abandoned.

Everything is built — the host, the Secure Enclave key, the sealing, the second
wrapping of the vault key. What macOS will not do is authorise the keychain
entitlement without an Apple provisioning profile embedded in an .app bundle,
which needs a paid developer account and renewing every year. Measured three
ways; see hosts/macos/README.md.

Installing anyway is still useful: `probe` works, and the day a profile exists
this is the binary it will sign. BENCpass will show it as unavailable until then
rather than offering a switch that cannot work.

NOTE

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

# ---- prove the thing that was just built actually answers -------------------
#
# The browser will not tell you which binary it started, and a stale one fails in
# ways that look like the code being wrong — an error message from a design that
# was replaced reads exactly like the current design failing. So the freshly
# built host is asked `hello` here, before anything is registered, and its answer
# is printed.
#
# The framing is native messaging's: a little-endian uint32 length, then the
# JSON. Written with printf rather than python, which is not on every Mac.
say_hello() {
  msg='{"v":1,"op":"hello"}'
  len=${#msg}
  prefix=$(printf '\\%03o\\%03o\\%03o\\%03o' \
    $((len % 256)) $(((len / 256) % 256)) $(((len / 65536) % 256)) $(((len / 16777216) % 256)))
  # tail -c +5 drops the reply's own four-byte length prefix.
  printf "$prefix%s" "$msg" | "$binary" 2>/dev/null | tail -c +5
}

reply=$(say_hello || true)
case $reply in
  *'"ok":true'*)
    echo "host answers: $reply"
    ;;
  *)
    echo "The host was built but did not answer. It will not work." >&2
    echo "  binary: $binary" >&2
    echo "  reply : ${reply:-(nothing)}" >&2
    exit 1
    ;;
esac

case $reply in
  *'"biometrics":"none"'*)
    echo
    echo "Note: this Mac reports no usable Touch ID right now, so BENCpass will"
    echo "not offer to turn it on. Check System Settings -> Touch ID & Password."
    ;;
esac

# ---- register ---------------------------------------------------------------

echo "$manifest_dirs" | while IFS= read -r dir; do
  mkdir -p "$dir"
  cat > "$dir/$name.json" <<EOF
{
  "name": "$name",
  "description": "BENCpass biometric unlock",
  "path": "$binary",
  "type": "stdio",
  "allowed_extensions": ["$extension_id"]
}
EOF
  echo "installed $dir/$name.json"
done

cat <<'EOF'

Now start the browser — for the test profile, that is tools/run-extension.sh.
The manifest belongs to your user account rather than to a profile, so the
temporarily-installed extension can reach it just as a permanently installed one
would. Quit any test browser already running first: it read the list of hosts at
startup, before this file existed.

Then, under the gear in the manager, turn on biometric unlock. You will be asked
for your master password once, to wrap the vault key for the keystore — see the
second-wrapping notes in src/core/vault.js for why that is unavoidable.
EOF
