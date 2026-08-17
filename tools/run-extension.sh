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
#   tools/run-extension.sh verbose    show everything, rather than a summary
#
# web-ext runs verbose whether or not you ask, into a log. It has to: the
# browser's own stdout and stderr reach web-ext's output only at debug level,
# and they are the only place that says why a debugger port never opened —
# which is the failure this script kept hitting, reported as nothing more
# helpful than `connect ECONNREFUSED 127.0.0.1:<port>`. That message means
# web-ext gave up after thirty seconds of dialling the port it asked the
# browser to open. The browser always says which of four things happened; it
# was simply never being listened to. `verbose` only changes what is shown on
# screen, not what is recorded.
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

set -- --source-dir="$root/src" \
       --firefox="$browser" \
       --firefox-profile="$profile" \
       --profile-create-if-missing \
       --keep-profile-changes \
       --start-url "http://127.0.0.1:$port/tools/testpage/index.html" \
       --browser-console

# Updates off, and the reasons are long enough to live in their own file —
# which is also the file the PowerShell script and the self-test read, so the
# three cannot drift the way they had.
while IFS= read -r pref; do
  case $pref in '' | \#*) continue ;; esac
  set -- "$@" --pref "$pref"
done < "$root/tools/test-prefs.txt"

set -- "$@" --verbose

# Another instance already holding this profile is the one cause that produces
# an intermittent failure — it works, then it does not, with nothing changed.
# A warning rather than a refusal: pgrep can match something else.
if command -v pgrep >/dev/null 2>&1 && pgrep -f "$profile" >/dev/null 2>&1; then
  echo "warning: something is already running with $profile." >&2
  echo "         A second instance cannot open the debugger port, and this run" >&2
  echo "         will fail with ECONNREFUSED. Quit it, or use a different port." >&2
  echo >&2
fi

log="$root/build/logs/web-ext.log"
mkdir -p "$root/build/logs"

# The status has to come out of the brace group, because a pipeline reports the
# exit code of its last command and that is the filter, not web-ext.
#
# Written only on failure, and by an `||` branch: `npx ...; echo $?` cannot work
# here, because under `set -e` a non-zero exit kills the subshell before the
# echo runs — which left the status file empty in exactly the case it existed
# for. On the left of `||` a command is exempt from errexit.
status=$(mktemp)
{ npx web-ext run "$@" || echo $? >"$status"; } 2>&1 | tee "$log" | if [ -n "$verbose" ]; then
  cat
else
  # Drop the debug chatter and strip the file-path prefix from the rest, which
  # leaves roughly what a non-verbose run used to print. fflush because this is
  # a long-running command whose output is watched as it happens, and awk's
  # buffering would otherwise hold lines back until it exits.
  awk '/^\[.*\]\[debug\] / { next } { sub(/^\[[^]]*\]\[[a-z]+\] /, ""); print; fflush() }'
fi

code=$(cat "$status")
rm -f "$status"
# Empty means web-ext never failed. An `if`, not `[ ... ] && exit`: under
# `set -e` a failing test at the end of an && list takes the script down with
# it, which here would mean exiting at the exact moment there is something to
# explain.
if [ -z "$code" ]; then
  exit 0
fi

# ---- what the browser said -------------------------------------------------
#
# Four outcomes, and DevToolsStartup dumps a distinct line for three of them.
# From handleDevToolsServerFlag: it returns silently when devtools are disabled
# by policy, complains by name when the two prefs it needs are not both true,
# reports the exception when the socket will not open, and otherwise announces
# the port. The fourth case is no line at all, which means the command-line
# handler never ran.
if grep -q 'ECONNREFUSED' "$log"; then
  echo >&2
  echo "The browser started but never opened its debugger port." >&2
  echo >&2
  if grep -q 'Could not run chrome debugger' "$log"; then
    echo "  It needs devtools.chrome.enabled and devtools.debugger.remote-enabled" >&2
    echo "  and did not have both. tools/test-prefs.txt sets the first; web-ext" >&2
    echo "  reserves the second and refuses to let --pref touch it, so a build" >&2
    echo "  that forces it off cannot be run this way." >&2
  elif grep -q 'Unable to start devtools server' "$log"; then
    grep 'Unable to start devtools server' "$log" | tail -1 >&2
    echo "  The port could not be opened. Something else has it." >&2
  elif grep -q 'Started devtools server' "$log"; then
    echo "  It opened the port and web-ext still could not reach it. A firewall" >&2
    echo "  or a proxy on loopback is the usual reason." >&2
  else
    echo "  It never got as far as reading the flag. That means it exited during" >&2
    echo "  startup, or handed off to an instance that was already running." >&2
    echo "  Quit every window of this browser and try again; if it persists," >&2
    echo "  'tools/run-extension.sh fresh' rules out the profile." >&2
  fi
  echo >&2
fi

echo "Full log: $log" >&2
exit "$code"
