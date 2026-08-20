#!/bin/sh
# Prove, in a real browser, the compartment behaviour BENCpass's design leans
# on. Nothing under test/ can do this: Node has no compartments to nuke.
#
# When an extension page closes, Firefox nukes its compartment, and anything
# another realm still holds from it becomes a dead-object wrapper that throws
# on every touch. The background once kept a Vault the manager document had
# built (setVault, gone now); the first tab closed after setup hit
# `vault.locked` in paintIcon and the extension was dead until restart. The fix
# is that the background builds every object it keeps, with only primitives
# crossing (MSG.SETUP carries the password as a string).
#
# This probe loads a tiny extension — tools/realm-probe/, not BENCpass — whose
# page hands its background one object by reference and one as a JSON string,
# then closes itself. The background reads both from tabs.onRemoved, the exact
# listener that first crashed. Expected, and required to pass:
#
#   by reference   THROWS "can't access dead object"   (the bug, still real)
#   built here     alive                               (the fix, still sound)
#
# If the first ever stops throwing, Firefox changed the rule and the comments
# explaining the design need revisiting; if the second ever throws, the fix's
# foundation is gone and the extension is in trouble. Either way, be told by
# this script rather than by a user.
set -eu

# Job control on, so every background job below becomes its own process group
# and can be killed as one. web-ext detaches the browser; killing web-ext alone
# leaves a headless browser and a copied profile behind. See selftest.sh.
set -m

root=$(cd "$(dirname "$0")/.." && pwd)
port=8736 # fixed, not ${PORT:-…}: the probe extension has it compiled in
logs="$root/build/logs"
mkdir -p "$logs"
result="$logs/realm-probe.json"
webext_log="$logs/realm-probe-webext.log"
rm -f "$result"

. "$root/tools/find-browser.sh"
browser=$BROWSER_BIN
echo "browser: $browser"
profile=$(mktemp -d)

BIND=127.0.0.1 RESULT_FILE="$result" node "$root/tools/serve.mjs" "$root" "$port" >/dev/null 2>&1 &
server=$!
cleanup() {
  kill $server 2>/dev/null || true
  kill -- -$webext 2>/dev/null || kill $webext 2>/dev/null || true
  rm -rf "$profile"
}
trap cleanup EXIT
sleep 0.5

set -- --source-dir="$root/tools/realm-probe" \
       --firefox="$browser" \
       --firefox-profile="$profile" \
       --profile-create-if-missing \
       --no-input \
       --arg=--headless

while IFS= read -r pref; do
  case $pref in '' | \#*) continue ;; esac
  set -- "$@" --pref "$pref"
done < "$root/tools/test-prefs.txt"

npx web-ext run "$@" >"$webext_log" 2>&1 &
webext=$!

i=0
while [ ! -f "$result" ] && [ $i -lt 90 ]; do
  sleep 1
  i=$((i + 1))
done

if [ ! -f "$result" ]; then
  echo "no result after ${i}s — web-ext log follows:" >&2
  tail -20 "$webext_log" >&2
  exit 1
fi

node -e '
const r = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
let bad = 0;
const check = (name, pass, detail) => {
  if (!pass) bad++;
  console.log(`  ${pass ? "PASS" : "FAIL"}  ${name}  [${detail}]`);
};
check(
  "an object kept by reference dies with its page",
  !r.byReference.ok && /dead object/.test(r.byReference.error ?? ""),
  r.byReference.ok ? `still alive, locked=${r.byReference.locked}` : r.byReference.error,
);
check(
  "an object the background built itself survives",
  r.builtHere.ok === true,
  r.builtHere.ok ? `alive, locked=${r.builtHere.locked}` : r.builtHere.error,
);
process.exit(bad ? 1 : 0);
' "$result"
