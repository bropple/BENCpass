#!/usr/bin/env python3
"""Convert the extension's web fonts into the TrueType the rescue tool embeds.

The rescue tool is a desktop program and cannot load woff2, so it carries the
same two typefaces as .ttf. Those bytes were previously produced by hand and
committed, which made them the one thing in this repository nobody could
regenerate — the same problem tools/vendor.sh exists to solve for argon2.js. A
font blob that cannot be reproduced is a font blob nobody can prove was not
swapped.

The conversion is lossless and structural: woff2 is a compression wrapper, so
dropping the flavour and saving writes the same glyphs, metrics and name table
back out. Everything except the OFL notice beside it comes from the woff2s in
src/ui/fonts/, which are themselves the fonts the extension actually ships.

Needs fonttools and brotli:

    python3 -m venv .venv && .venv/bin/pip install fonttools brotli
    .venv/bin/python tools/rescue-fonts.py

Regenerating will not produce byte-identical output across fonttools versions,
so — as with the icon — run it when the fonts change, look at the result, and
commit it. There is deliberately no CI check that re-renders and diffs.
"""

import pathlib
import sys

try:
    from fontTools.ttLib import TTFont
except ImportError:
    sys.exit("fonttools is not installed — see the header of this file")

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "ui" / "fonts"
DST = ROOT / "rescue" / "internal" / "ui" / "fonts"

FONTS = ("share-tech-mono", "vt323")


def main() -> None:
    DST.mkdir(parents=True, exist_ok=True)
    for name in FONTS:
        src = SRC / f"{name}.woff2"
        if not src.exists():
            sys.exit(f"missing {src}")
        font = TTFont(src)
        font.flavor = None  # drop the woff2 wrapper
        out = DST / f"{name}.ttf"
        font.save(out)

        # The notice has to name the font it travels with. It did not once:
        # both copies of OFL.txt were the Terminus one, copied from
        # assets/fonts/, while these two are Share Tech Mono and VT323.
        copyright = next(
            str(r) for r in TTFont(out)["name"].names if r.nameID == 0
        )
        print(f"{out.relative_to(ROOT)}  <-  {copyright[:60]}...")

    print("\nCheck rescue/internal/ui/fonts/OFL.txt still names these two fonts.")


if __name__ == "__main__":
    main()
