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

# A dedicated profile kept between runs, rather than a fresh one each time.
# Recreating the vault on every launch makes autofill essentially untestable.
# tools/run-extension.sh fresh  wipes it.
profile="$root/.bencpass-profile"
# An `if`, not `[ ... ] && rm`: under `set -e` a failed test at the end of an
# && list takes the whole script down with it, so a normal run would exit here
# without starting anything.
if [ "${1:-}" = "fresh" ]; then
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

npx web-ext run "$@"
