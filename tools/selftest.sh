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

# Job control on, so every background job below becomes its own process group
# and can be killed as one. This is not decoration: web-ext copies the profile
# into a temp directory of its own and starts the browser as a detached child,
# so killing web-ext leaves the browser running with a 117 MB profile behind
# it. Twenty of those accumulated over a day and a half of probe runs on the
# machine this was written on — five gigabytes of resident memory and two and a
# half of /tmp, held by browsers nobody could see.
set -m

root=$(cd "$(dirname "$0")/.." && pwd)
port=${PORT:-8734}
logs="$root/build/logs"
mkdir -p "$logs"
result=${RESULT_FILE:-$logs/selftest.json}
webext_log="$logs/selftest-webext.log"
. "$root/tools/find-browser.sh"
browser=$BROWSER_BIN
profile=$(mktemp -d)
echo "browser: $browser"

# web-ext copies the profile into $TMPDIR/copy-* on every launch and removes it
# only on the clean shutdown it never gets here: the teardown below kills the
# browser's process group, which is right, and orphans the copy — thirty runs
# left 1.5 GB of dead profiles in /tmp in one day. So web-ext gets a temp
# directory of its own, set on its command line rather than exported, and the
# trap removes the whole thing. Everything this run copies dies with it, and
# nothing anyone else put in /tmp is ours to touch.
webext_tmp=$(mktemp -d)

rm -f "$result"

RESULT_FILE="$result" node "$root/tools/serve.mjs" "$root" "$port" >/dev/null 2>&1 &
server=$!
cleanup() {
  kill $server 2>/dev/null || true
  # The whole group: web-ext detaches the browser, so killing web-ext
  # alone leaves it running. The leading dash means the process group.
  kill -- -$webext 2>/dev/null || kill $webext 2>/dev/null || true
  # The kill is asynchronous, and removing the temp directories while the
  # group is still dying loses a race: node rebuilds its compile cache under
  # $webext_tmp as it exits, rm sees files appear behind itself, and the
  # directory survives — observed, 2.3 MB of node-compile-cache left from one
  # run. Reap web-ext, then wait (bounded) for the whole group to be gone.
  wait $webext 2>/dev/null || true
  i=0
  while kill -0 -- -$webext 2>/dev/null && [ $i -lt 50 ]; do
    sleep 0.1
    i=$((i + 1))
  done
  rm -rf "$profile" "$webext_tmp"
}
trap cleanup EXIT
sleep 0.5

set -- --source-dir="$root/src" \
       --firefox="$browser" \
       --firefox-profile="$profile" \
       --profile-create-if-missing \
       --no-input \
       --arg=--headless \
       --start-url "http://127.0.0.1:$port/tools/testpage/index.html?selftest"

# The same prefs the interactive script uses. This one runs headless against a
# throwaway profile, but it is still a second instance of the browser you use,
# and it can nag it to restart just as readily.
while IFS= read -r pref; do
  case $pref in '' | \#*) continue ;; esac
  set -- "$@" --pref "$pref"
done < "$root/tools/test-prefs.txt"

TMPDIR=$webext_tmp npx web-ext run "$@" >"$webext_log" 2>&1 &
webext=$!

# The page reports after roughly eight seconds of scripted interaction.
i=0
while [ ! -f "$result" ] && [ $i -lt 60 ]; do
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
