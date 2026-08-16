#!/bin/sh
# Copy the assets the extension needs into its own root.
#
# A manifest cannot reference a path outside the extension directory, so the
# fonts have to live under src/. This keeps that copy honest rather than letting
# it drift — a webfont that silently fails to load is invisible until someone
# notices the headings look wrong.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$root/src/ui/fonts"
for f in vt323.woff2 share-tech-mono.woff2 OFL.txt; do
  cp "$root/assets/fonts/$f" "$root/src/ui/fonts/$f"
done
echo "src/ui/fonts/{vt323.woff2,share-tech-mono.woff2,OFL.txt}"
