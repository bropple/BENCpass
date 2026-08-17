#!/bin/sh
# Regenerate the BENCpass icon set from one SVG.
#
# Per benco-build-and-packaging.md §2: generated art is committed, not built at
# release time. Run this when the artwork changes, LOOK AT WHAT CAME OUT, and
# commit it. A release runner should not need librsvg installed, and art that
# regenerates on every release is art that can silently change.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
src="$root/assets/icon/bencpass.svg"
out="$root/assets/icon"

command -v rsvg-convert >/dev/null || { echo "need librsvg (rsvg-convert)" >&2; exit 1; }
command -v magick >/dev/null || { echo "need ImageMagick" >&2; exit 1; }

for size in 16 32 48 64 128 256 512; do
  rsvg-convert -w "$size" -h "$size" "$src" -o "$out/bencpass-$size.png"
  printf 'bencpass-%s.png ' "$size"
done
echo

# Windows and the browser tab both want a multi-size .ico. Built from the PNGs
# rather than re-rendered, so the .ico cannot disagree with them.
magick "$out/bencpass-16.png" "$out/bencpass-32.png" "$out/bencpass-48.png" \
       "$out/bencpass-64.png" "$out/bencpass-128.png" "$out/bencpass-256.png" \
       "$out/bencpass.ico"
echo "bencpass.ico"

# The server embeds the same SVG for its status page, so the art has exactly one
# source. Copied rather than hand-inlined into Go, which would be a second copy
# free to drift.
cp "$src" "$root/server/static/bencpass.svg"
echo "server/static/bencpass.svg"

# The extension needs the PNGs inside its own root, since a manifest cannot
# reference a path outside it.
mkdir -p "$root/src/ext/icons"
for size in 16 32 48 64 128; do
  cp "$out/bencpass-$size.png" "$root/src/ext/icons/$size.png"
done
echo "src/ext/icons/{16,32,48,64,128}.png"

# The locked variant, red visor stripe, for the toolbar icon while the vault is
# shut. Same mark, one colour different — it reads at 16px because the stripe is
# the only saturated thing in it.
for size in 16 32 48 64 128; do
  rsvg-convert -w "$size" -h "$size" "$out/bencpass-locked.svg" \
    -o "$root/src/ext/icons/$size-locked.png"
done
echo "src/ext/icons/{16,32,48,64,128}-locked.png"
