#!/bin/sh
# Load BENCpass into a scratch Zen profile and open the form-shapes page.
#
# A temporary profile, deliberately: the extension is installed unsigned and
# temporarily, so nothing touches the browser you actually use and the vault
# created here is thrown away with the profile.
#
# The test page is served over http://127.0.0.1, which counts as a private host
# — so filling is allowed without a certificate, and the insecure-page refusal
# is not in the way of testing everything else. To exercise that refusal, point
# a hosts entry at 127.0.0.1 and browse to it by name instead.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
port=${PORT:-8731}
browser=${BROWSER_BIN:-$(command -v zen-browser || command -v firefox)}

[ -n "$browser" ] || { echo "no zen-browser or firefox on PATH" >&2; exit 1; }

node "$root/tools/serve.mjs" "$root" "$port" >/dev/null 2>&1 &
server=$!
trap 'kill $server 2>/dev/null || true' EXIT
sleep 0.5

echo "form shapes:  http://127.0.0.1:$port/tools/testpage/index.html"
echo "manager:      about:addons -> BENCpass -> Preferences"
echo

npx web-ext run \
  --source-dir="$root/src" \
  --firefox="$browser" \
  --start-url "http://127.0.0.1:$port/tools/testpage/index.html" \
  --browser-console
