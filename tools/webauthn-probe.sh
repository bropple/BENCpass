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

BIND=localhost RESULT_FILE="$result" node "$root/tools/serve.mjs" "$root" "$port" >/dev/null 2>&1 &
server=$!
cleanup() { kill $server 2>/dev/null || true; rm -rf "$profile"; }
trap cleanup EXIT
sleep 0.5

# localhost, not 127.0.0.1. Both are secure contexts, but an IP address is not a
# registrable domain and WebAuthn will not accept an RP ID from one.
url="http://localhost:$port/tools/webauthn-probe/index.html"

# Reading capabilities needs no window. Actually creating a credential needs a
# user gesture and raises a prompt, so that half cannot be headless — and it is
# the half that answers the question on a machine with a sensor.
if [ "${1:-}" = "live" ]; then
  echo "opening a browser. Press the button, and use the sensor when asked."
  echo
  "$BROWSER_BIN" --profile "$profile" "$url" >/dev/null 2>&1 &

  # Waiting for the file to *exist* is wrong here: the page posts its
  # capabilities on load, which creates it within a second, and the browser was
  # then shut before anyone could reach the button. Wait for the verdict, which
  # only the test itself writes.
  i=0
  while [ $i -lt 300 ]; do
    if [ -f "$result" ] && grep -q '"verdict"' "$result" 2>/dev/null; then break; fi
    sleep 1
    i=$((i + 1))
  done

  if ! grep -q '"verdict"' "$result" 2>/dev/null; then
    echo "No verdict after ${i}s — the button was not pressed, or the prompt was" >&2
    echo "dismissed. What was read on load:" >&2
  fi
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
