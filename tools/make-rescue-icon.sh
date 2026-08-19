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

if ! command -v rsvg-convert >/dev/null; then
  echo "rsvg-convert is not installed (librsvg)." >&2
  exit 1
fi

# 512 square. Fyne scales it down for the window and the launcher, and every
# platform's packaging wants at least this much to work from.
rsvg-convert -w 512 -h 512 "$src" -o "$out"
echo "wrote ${out#"$root/"} ($(wc -c < "$out") bytes)"
echo "Look at it before committing: the kit has to still read at 32 pixels."
