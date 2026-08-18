#!/bin/sh
# Ask the native host what this machine will actually allow, and print it.
#
# The one question CI cannot answer: a runner has no fingerprint enrolled, so
# every biometric variant fails before it reaches the part being tested. This has
# to run on a Mac with Touch ID set up.
#
# It stores nothing. Each key it makes is deleted again immediately.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
binary="$root/build/hosts/bencpass-auth"

if [ ! -x "$binary" ]; then
  echo "No host at $binary — run hosts/install.sh first." >&2
  exit 1
fi

msg='{"v":1,"op":"probe"}'
len=${#msg}
prefix=$(printf '\\%03o\\%03o\\%03o\\%03o' \
  $((len % 256)) $(((len / 256) % 256)) $(((len / 65536) % 256)) $(((len / 16777216) % 256)))

printf "$prefix%s" "$msg" | "$binary" | tail -c +5 |
  # Readable without needing a JSON tool installed.
  sed -e 's/,"/,\n  "/g' -e 's/^{/{\n  /' -e 's/}$/\n}/'
echo
