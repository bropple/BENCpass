#!/usr/bin/env bash
# The system packages the rescue tool needs to compile on Linux.
#
# One script rather than a list repeated in four workflow steps — build, test,
# release and the vulnerability scan all need exactly the same set, and four
# copies is how three of them end up right.
#
# xorg-dev alone is what Fyne's own instructions say, and it is not enough:
# GLFW 3.4 builds its Wayland backend as well as its X11 one, so it wants
# wayland-client-core.h and xkbcommon too. The failure names a header, from a
# job that never mentions graphics, which is a poor way to find that out twice.
#
#   tools/linux-gui-deps.sh
set -euo pipefail

sudo apt-get update
sudo apt-get install -y \
  libgl1-mesa-dev \
  xorg-dev \
  libwayland-dev \
  libxkbcommon-dev \
  wayland-protocols \
  libdecor-0-dev
