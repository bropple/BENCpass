# Fonts

`TerminusTTF.ttf` — Terminus (TTF) 4.49.3, the TrueType conversion of Dimitar
Zhekov's Terminus by Tilman Blumenbach. <https://files.ax86.net/terminus-ttf/>

**Bundled unmodified, and that is deliberate.** The SIL Open Font License permits
bundling and redistributing the font with software; it reserves the names
"Terminus Font" and "Terminus (TTF)" against *modified* versions. Shipping the
file exactly as released keeps that question from arising at all — so do not
subset it to save space, and do not re-generate it. `OFL.txt` is the licence and
must travel with any binary that embeds this.

Only the regular weight is here. The GUI uses one weight at three sizes, and
Terminus is a bitmap design: it is sharp at its native sizes with point
filtering and mushy between them, which is why `bm_ui.c` loads it at 16, 20 and
32 rather than scaling one instance.
