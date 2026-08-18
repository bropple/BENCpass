#!/bin/sh
# Serve the repo root and open the manager against a throwaway seeded vault.
#
# A server is required rather than convenient: Firefox refuses to load ES
# modules from file://, because a file:// document has an opaque origin and the
# module fetch is then subject to CORS.
#
#   tools/preview.sh              serve, print the URLs
#   tools/preview.sh shot         serve and write screenshots to .preview/
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
port=${PORT:-8731}
# Generated into build/, not next to the source it is generated from. A file
# that appears inside src/ dirties the working tree for reasons nobody can
# account for later, and src/ is what web-ext packages — a stray page there can
# end up inside the extension.
out_dir="$root/build/preview"
gen="$out_dir/manager.html"
toast_gen="$out_dir/toast.html"
complaints="$root/build/logs/preview-errors.json"
mkdir -p "$out_dir"

# The preview page is the real manager.html with its script swapped, so the
# markup cannot drift between what is previewed and what ships. The held script
# is added only for screenshots; see tools/serve.mjs for why.
build_page() {
  sed -e 's|src="manager.js"|src="/tools/preview.js"|' \
      -e 's|href="style.css"|href="/src/ui/style.css"|' \
    "$root/src/ui/manager.html" > "$gen"
  if [ -n "${1:-}" ]; then
    sed -i "s|</body>|<script defer src=\"/__hold?ms=$1\"></script></body>|" "$gen"
  fi
}

# The save prompt, the same way: the real markup and stylesheet with only the
# script swapped, so a screenshot is of the thing that ships.
build_toast() {
  sed -e 's|src="toast.js"|src="/tools/toast-preview.js"|' \
      -e 's|href="toast.css"|href="/src/ext/toast.css"|' \
      -e 's|src="icons/32.png"|src="/src/ext/icons/32.png"|' \
    "$root/src/ext/toast.html" > "$toast_gen"
  # The toast draws itself from a message posted after its module has run, so
  # the load event fires before there is anything on screen and a screenshot
  # taken then catches the placeholder. Same hold as the manager uses.
  if [ -n "${1:-}" ]; then
    printf '<script defer src="/__hold?ms=%s"></script>\n' "$1" >> "$toast_gen"
  fi
}

mkdir -p "$root/build/logs"
rm -f "$complaints"
RESULT_FILE="$complaints" node "$root/tools/serve.mjs" "$root" "$port" >/dev/null 2>&1 &
server=$!
cleanup() { kill $server 2>/dev/null || true; rm -f "$gen" "$toast_gen"; }
trap cleanup EXIT
sleep 0.5

base="http://127.0.0.1:$port/build/preview/manager.html"
toast_base="http://127.0.0.1:$port/build/preview/toast.html"

if [ "${1:-}" = "shot" ]; then
  build_page 3000
  build_toast 3000
  . "$root/tools/find-browser.sh"
  browser=$BROWSER_BIN
  out="$root/screenshots"
  rm -f "$out"/*.png
  mkdir -p "$out"
  profile=$(mktemp -d)
  cleanup() { kill $server 2>/dev/null || true; rm -f "$gen" "$toast_gen"; rm -rf "$profile"; }

  shot() {
    "$browser" --headless --profile "$profile" --window-size="${3:-1280,820}" \
      --screenshot "$out/$1.png" "$base$2" >/dev/null 2>&1
    echo "  screenshots/$1.png"
  }

  echo "screenshots:"
  # Gate states, at the size the gate is actually used at.
  shot 01-setup      '?fresh'                        900,700
  shot 02-locked     ''                              900,700
  shot 03-wrong      '?wrong'                        900,700
  # The vault, empty and then populated.
  shot 04-empty      '?empty&open'
  shot 05-list       '?open&select=0&reveal'
  shot 06-stale      '?open&select=2&reveal'
  shot 07-reused     '?open&select=1&reveal'
  shot 08-imported   '?open&select=3'
  # Editing, generating, searching.
  shot 09-edit       '?open&select=0&edit'
  shot 10-edit-shown '?open&select=0&edit&show'
  shot 11-new        '?open&new'
  shot 12-generated  '?open&new&gen'
  shot 13-search     '?open&search=example&select=0'
  shot 14-no-match   '?open&search=nothing+matches+this'
  # Sidebar width, where the two-pane split has to stack or the detail pane
  # is squeezed to nothing.
  shot 15-narrow     '?open&select=0'                400,900
  # The addresses section, and the address editor — closed and opened, since
  # the less-common fields are behind a disclosure.
  shot 16-addresses  '?open&section=address&select=0'
  shot 17-address-edit '?open&section=address&select=1&edit'      1280,1100
  shot 18-address-more '?open&section=address&select=1&edit&more' 1280,1400

  # Settings, in the states worth looking at.
  shot 19-settings   '?open&settings'                    1280,1000
  shot 20-settings-bio '?open&settings&bio=ready'        1280,1000
  shot 20b-settings-narrow '?open&settings&bio=ready'    460,1000

  # The save prompt, at the size the content script frames it at.
  toast() {
    "$browser" --headless --profile "$profile" --window-size="$3" \
      --screenshot "$out/$1.png" "$toast_base$2" >/dev/null 2>&1
    echo "  screenshots/$1.png"
  }
  toast 21-toast-save    '?kind=login'          330,104
  toast 22-toast-update  '?kind=login&update'   330,104
  toast 23-toast-address '?kind=address'        330,148

  # Any error the pages hit on the way, reported by the harness. This turns a
  # screenshot run into a check that the UI actually boots — which is worth
  # having, because a manager whose module fails to load renders its own static
  # markup and looks exactly like a locked vault waiting for a password.
  if [ -s "$complaints" ]; then
    echo >&2
    echo "The UI reported errors while these were taken:" >&2
    sed 's/^/  /' "$complaints" >&2
    exit 1
  fi
  echo "  (no errors reported by the pages)"
  exit 0
fi

build_page
build_toast
echo "BENCpass preview:"
echo "  $base                 locked"
echo "  $base?open            unlocked"
echo "  $base?open&select     an entry selected"
echo "  $toast_base?kind=address   the save prompt"
echo
echo "Master password for the seeded vault: preview-only-not-a-real-vault"
echo "Ctrl-C to stop."
wait $server
