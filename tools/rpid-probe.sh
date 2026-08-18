#!/bin/sh
# Which RP IDs will Firefox accept from an *extension* page?
#
# A moz-extension:// origin has no registrable domain, so WebAuthn cannot derive
# a relying party from it and refuses with "SecurityError: The operation is
# insecure". Firefox 150 lets an extension assert an RP ID for a domain it holds
# host permissions for — but which strings qualify is a question about Firefox,
# and the answer decides a value that can never change afterwards, because every
# credential is bound to it.
#
# Runs anywhere, including a machine with no authenticator at all: the RP ID is
# validated before any authenticator is consulted, so a rejected one gives
# SecurityError while an accepted one gives NotAllowedError for want of a
# fingerprint. Those are the two answers being told apart.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
port=${PORT:-8739}
work="$root/build/rpid-test"
logs="$root/build/logs"
mkdir -p "$logs"
result="$logs/rpid.json"
rm -f "$result"

# A copy of the extension with one extra page, so nothing experimental can end
# up in the shipped source.
rm -rf "$work"
mkdir -p "$work"
cp -R "$root/src/." "$work/"

cat > "$work/rpid.html" <<'HTML'
<!doctype html>
<meta charset="utf-8">
<title>RP ID probe</title>
<body><pre id="out">…</pre>
<script type="module" src="rpid.js"></script>
HTML

cat > "$work/rpid.js" <<'JS'
const CANDIDATES = [
  '',                    // unset — the current behaviour, expected to fail
  'bencpass.invalid',    // reserved by RFC 2606, guaranteed never to resolve
  'bencpass.local',
  'localhost',
  'ropple.net',          // a real registrable domain
  'bencpass.ropple.net',
];

const results = [];
for (const rpId of CANDIDATES) {
  try {
    await navigator.credentials.create({
      publicKey: {
        rp: rpId ? { id: rpId, name: 'BENCpass' } : { name: 'BENCpass' },
        user: { id: new Uint8Array(16), name: 'probe', displayName: 'probe' },
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        authenticatorSelection: { userVerification: 'required' },
        extensions: { prf: {} },
        timeout: 1,
      },
    });
    results.push({ rpId: rpId || '(unset)', verdict: 'accepted — and created one' });
  } catch (e) {
    // SecurityError is the RP ID being refused. Anything else means the RP ID
    // passed and the failure came later, which is the answer we want.
    results.push({
      rpId: rpId || '(unset)',
      verdict: e.name === 'SecurityError' ? 'REJECTED' : `accepted (then ${e.name})`,
    });
  }
}

document.getElementById('out').textContent = JSON.stringify(results, null, 2);
await fetch('http://127.0.0.1:PORT/__result', {
  method: 'POST',
  body: JSON.stringify({ origin: location.origin, results }, null, 2),
});
JS
sed -i "s|127.0.0.1:PORT|127.0.0.1:$port|" "$work/rpid.js"

# Opened at startup, since there is no other way to reach an extension page
# whose UUID is generated per profile.
python3 - "$work/manifest.json" <<'PY'
import json, sys
p = sys.argv[1]
m = json.load(open(p))
m.setdefault('web_accessible_resources', []).append('rpid.html')
json.dump(m, open(p, 'w'), indent=2)
PY
printf '\nbrowser.tabs.create({ url: browser.runtime.getURL("rpid.html") });\n' >> "$work/ext/background.js"

. "$root/tools/find-browser.sh"
RESULT_FILE="$result" node "$root/tools/serve.mjs" "$root" "$port" >/dev/null 2>&1 &
server=$!
profile=$(mktemp -d)
cleanup() { kill $server 2>/dev/null || true; kill $webext 2>/dev/null || true; rm -rf "$profile"; }
trap cleanup EXIT
sleep 0.5

npx web-ext run --source-dir="$work" --firefox="$BROWSER_BIN" \
  --firefox-profile="$profile" --profile-create-if-missing --no-input \
  --arg=--headless >"$logs/rpid-webext.log" 2>&1 &
webext=$!

i=0
while [ ! -f "$result" ] && [ $i -lt 45 ]; do sleep 1; i=$((i + 1)); done
if [ ! -f "$result" ]; then
  echo "no answer after ${i}s; tail of the web-ext log:" >&2
  tail -15 "$logs/rpid-webext.log" >&2
  exit 1
fi
cat "$result"
echo
