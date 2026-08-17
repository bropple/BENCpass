#!/bin/sh
# Load BENCpass into a test profile and open the form-shapes page.
#
# A dedicated profile at .bencpass-profile/, kept between runs so the vault
# survives — recreating it every launch makes autofill untestable. `fresh`
# discards it. The extension is installed unsigned and temporarily either way,
# so the browser you actually use is untouched.
#
# The test page is served over http://127.0.0.1, which counts as a private host
# — so filling is allowed without a certificate, and the insecure-page refusal
# is not in the way of testing everything else. To exercise that refusal, point
# a hosts entry at 127.0.0.1 and browse to it by name instead.
#
#   tools/run-extension.sh            run
#   tools/run-extension.sh fresh      wipe the test profile first
#   tools/run-extension.sh verbose    log what the browser prints
#
# `verbose` is the thing to reach for when web-ext ends in
# `connect ECONNREFUSED 127.0.0.1:<port>`. That is web-ext giving up after 30
# seconds of dialling the browser's debugger port: the browser started but
# never opened it. Only the browser's own stderr says why, and web-ext logs it
# at debug level, which --verbose turns on.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
port=${PORT:-8731}
. "$root/tools/find-browser.sh"
browser=$BROWSER_BIN

fresh=
verbose=
for arg in "$@"; do
  case $arg in
    fresh) fresh=1 ;;
    verbose) verbose=1 ;;
    *) echo "unknown argument: $arg (expected 'fresh' or 'verbose')" >&2; exit 2 ;;
  esac
done

node "$root/tools/serve.mjs" "$root" "$port" >/dev/null 2>&1 &
server=$!
trap 'kill $server 2>/dev/null || true' EXIT
sleep 0.5

# Which browser, always. Without this the only clue in a failed run is web-ext's
# own output, which never names the binary it was handed.
echo "browser:      $browser"
echo "form shapes:  http://127.0.0.1:$port/tools/testpage/index.html"
echo "manager:      about:addons -> BENCpass -> Preferences"
echo

# A dedicated profile kept between runs, rather than a fresh one each time.
# Recreating the vault on every launch makes autofill essentially untestable.
# tools/run-extension.sh fresh  wipes it.
profile="$root/.bencpass-profile"
# An `if`, not `[ ... ] && rm`: under `set -e` a failed test at the end of an
# && list takes the whole script down with it, so a normal run would exit here
# without starting anything.
if [ -n "$fresh" ]; then
  rm -rf "$profile"
  echo "wiped $profile"
fi

# Updates off, and thoroughly. A second instance starting up will otherwise
# check for, stage and apply an update to the shared installation — at which
# point the browser you actually use notices its own files have changed
# underneath it and demands a restart. That is the whole cause of the nag.
#
# The rest silence first-run behaviour that has nothing to offer a test profile.
prefs="
app.update.auto=false
app.update.enabled=false
app.update.checkInstallTime=false
app.update.staging.enabled=false
app.update.service.enabled=false
app.update.background.scheduling.enabled=false
app.update.notifyDuringDownload=false
extensions.update.enabled=false
extensions.update.autoUpdateDefault=false
browser.shell.checkDefaultBrowser=false
browser.startup.homepage_override.mstone=ignore
browser.aboutwelcome.enabled=false
datareporting.policy.dataSubmissionEnabled=false
toolkit.telemetry.reportingpolicy.firstRun=false
"

set -- --source-dir="$root/src" \
       --firefox="$browser" \
       --firefox-profile="$profile" \
       --profile-create-if-missing \
       --keep-profile-changes \
       --start-url "http://127.0.0.1:$port/tools/testpage/index.html" \
       --browser-console

for pref in $prefs; do
  set -- "$@" --pref "$pref"
done

if [ -n "$verbose" ]; then
  set -- "$@" --verbose
fi

npx web-ext run "$@"
