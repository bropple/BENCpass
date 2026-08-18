#!/bin/sh
# Ask this browser whether it can do WebAuthn PRF, and whether it can see a
# built-in authenticator.
#
# PRF is what would let BENCpass derive a key from Touch ID or Hello *through
# the browser*, with no native host, no entitlement and no token. It is the one
# route to the fingerprint sensor already in the machine. Whether Firefox has
# shipped it is a fact about the browser in front of you rather than about the
# documentation, so this asks it.
#
#   tools/webauthn-probe.sh         read capabilities, headless
#   tools/webauthn-probe.sh live    open a window and test it for real
#
# Without `live` nothing is created and no prompt is raised.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
port=${PORT:-8736}
logs="$root/build/logs"
mkdir -p "$logs"
result="$logs/webauthn.json"
rm -f "$result"

. "$root/tools/find-browser.sh"
echo "browser: $BROWSER_BIN"
profile=$(mktemp -d)

RESULT_FILE="$result" node "$root/tools/serve.mjs" "$root" "$port" >/dev/null 2>&1 &
server=$!
cleanup() { kill $server 2>/dev/null || true; rm -rf "$profile"; }
trap cleanup EXIT
sleep 0.5

url="http://127.0.0.1:$port/tools/webauthn-probe/index.html"

# Reading capabilities needs no window. Actually creating a credential needs a
# user gesture and raises a prompt, so that half cannot be headless — and it is
# the half that answers the question on a machine with a sensor.
if [ "${1:-}" = "live" ]; then
  echo "opening a browser. Press the button, and use the sensor when asked."
  echo "Ctrl-C here when you are done."
  "$BROWSER_BIN" --profile "$profile" "$url" >/dev/null 2>&1 &
  i=0
  while [ ! -f "$result" ] && [ $i -lt 300 ]; do sleep 1; i=$((i + 1)); done
  sleep 2
else
  "$BROWSER_BIN" --headless --profile "$profile" \
    --screenshot /dev/null "$url" >/dev/null 2>&1 || true
  i=0
  while [ ! -f "$result" ] && [ $i -lt 20 ]; do sleep 1; i=$((i + 1)); done
fi

if [ ! -f "$result" ]; then
  echo "no answer after ${i}s" >&2
  exit 1
fi
cat "$result"
echo
