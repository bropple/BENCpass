#!/usr/bin/env bash
# Render the rescue tool's icon from its single SVG source.
#
# Generated art is committed rather than built at release time, per
# style/benco-build-and-packaging.md: a release runner should not have to
# install librsvg, and art that regenerates on every release is art that can
# silently change. So run this when the artwork changes, LOOK AT WHAT CAME OUT,
# and commit it.
#
# Deliberately not checked in CI by re-rendering and diffing. Two versions of
# librsvg can disagree in the last bit of an antialiased pixel, and a check that
# turns a correct icon red is a check everyone learns to ignore.
#
#   tools/make-rescue-icon.sh
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
src="$root/assets/brand/benco-gon-medic.svg"
out="$root/rescue/internal/ui/icon.png"
ico="$root/rescue/internal/ui/bencpass-rescue.ico"
syso="$root/rescue/rsrc_windows_amd64.syso"

if ! command -v rsvg-convert >/dev/null; then
  echo "rsvg-convert is not installed (librsvg)." >&2
  exit 1
fi

# 512 square. Fyne scales it down for the window and the launcher, and every
# platform's packaging wants at least this much to work from.
rsvg-convert -w 512 -h 512 "$src" -o "$out"
echo "wrote ${out#"$root/"} ($(wc -c < "$out") bytes)"
echo "Look at it before committing: the kit has to still read at 32 pixels."

# The Windows icon, which is a different thing from the window's icon.
#
# icon.png above is what the program hands the toolkit at runtime. It has no
# bearing on the file sitting in Explorer or pinned to a taskbar: that comes
# from an icon resource compiled into the .exe itself, and without one Windows
# draws the Go gopher's default. Which is what it drew.
#
# `go build` links any *_windows_*.syso beside the package automatically, so the
# resource is committed like the rest of the generated art rather than built on
# a release runner. rsrc is the only thing here that needs the network, which is
# the other reason this is a human's command and not CI's.
if ! command -v magick >/dev/null; then
  echo "ImageMagick is not installed; skipping the Windows icon." >&2
  exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Every size Windows asks for: 16 in the title bar, 32 in Explorer's list, 48
# for its medium icons, 256 for the extra-large view and the Alt-Tab card.
for size in 16 24 32 48 64 128 256; do
  rsvg-convert -w "$size" -h "$size" "$src" -o "$tmp/$size.png"
done
magick "$tmp/16.png" "$tmp/24.png" "$tmp/32.png" "$tmp/48.png" \
       "$tmp/64.png" "$tmp/128.png" "$tmp/256.png" "$ico"
echo "wrote $ico"

go run github.com/akavel/rsrc@v0.10.2 -ico "$ico" -arch amd64 -o "$syso"
echo "wrote $syso"
