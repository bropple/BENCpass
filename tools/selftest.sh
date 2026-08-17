#!/bin/sh
# Drive the extension in a real browser, without a person, and print the result.
#
# There is no way to click a web-ext-launched browser from outside it and no way
# to screenshot it separately. So the page drives the extension itself — page
# script and the content script share a DOM, and an event dispatched from one
# reaches the other's listeners — and posts its findings back to the local
# server, which writes them where this script can read them.
#
# The vault is locked throughout, because nothing can type a master password
# into the manager. That still covers the part that has broken repeatedly:
# which fields get anchored, what those anchors look like, whether the menu
# opens and stays open, and that nothing is ever filled unasked.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
port=${PORT:-8734}
result=${RESULT_FILE:-/tmp/bencpass-selftest.json}
browser=${BROWSER_BIN:-$(command -v zen-browser || command -v firefox)}
profile=$(mktemp -d)

rm -f "$result"

RESULT_FILE="$result" node "$root/tools/serve.mjs" "$root" "$port" >/dev/null 2>&1 &
server=$!
cleanup() {
  kill $server 2>/dev/null || true
  kill $webext 2>/dev/null || true
  rm -rf "$profile"
}
trap cleanup EXIT
sleep 0.5

npx web-ext run \
  --source-dir="$root/src" \
  --firefox="$browser" \
  --firefox-profile="$profile" \
  --profile-create-if-missing \
  --no-input \
  --arg=--headless \
  --start-url "http://127.0.0.1:$port/tools/testpage/index.html?selftest" \
  --pref app.update.auto=false \
  --pref app.update.enabled=false \
  --pref browser.shell.checkDefaultBrowser=false \
  >/tmp/bencpass-webext.log 2>&1 &
webext=$!

# The page reports after roughly eight seconds of scripted interaction.
i=0
while [ ! -f "$result" ] && [ $i -lt 60 ]; do
  sleep 1
  i=$((i + 1))
done

if [ ! -f "$result" ]; then
  echo "no result after ${i}s — web-ext log follows:" >&2
  tail -20 /tmp/bencpass-webext.log >&2
  exit 1
fi

node -e '
const r = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
if (r.fatal) { console.log("FATAL:", r.fatal); process.exit(1); }

console.log("\nanchors placed:");
for (const a of r.anchors) {
  console.log(`  form ${a.section.padEnd(2)} ${String(a.field).padEnd(28)} ${a.title}`);
}

console.log("\nchecks:");
let bad = 0;
for (const c of r.checks) {
  if (!c.pass) bad++;
  console.log(`  ${c.pass ? "PASS" : "FAIL"}  ${c.name}${c.detail ? "  [" + c.detail + "]" : ""}`);
}
console.log(`\n${r.checks.length - bad}/${r.checks.length} passed`);
process.exit(bad ? 1 : 0);
' "$result"
