#!/usr/bin/env bash
# The system packages the rescue tool needs to compile on Linux.
#
# One script rather than a list repeated in five workflow steps — build, test,
# release, CodeQL and the vulnerability scan all need exactly the same set, and
# five copies is how four of them end up right.
#
# xorg-dev alone is what Fyne's own instructions say, and it is not enough:
# GLFW 3.4 builds its Wayland backend as well as its X11 one, so it wants
# wayland-client-core.h and xkbcommon too. The failure names a header, from a
# job that never mentions graphics, which is a poor way to find that out twice.
#
#   tools/linux-gui-deps.sh
set -euo pipefail

# Non-interactive, or apt can sit for ever on a configuration prompt with
# nobody there to answer it. This step hung for over half an hour on a runner
# having worked fine on the same script an hour earlier, which is what an
# unanswered prompt or a held dpkg lock looks like from outside.
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

# timeout wraps apt-get rather than this function, because timeout execs a
# binary and cannot see a shell function — an earlier draft of this file put
# `timeout` in front of the wrapper, which would have quietly run the system
# apt with no sudo and none of these options.
apt_get() {
  sudo timeout 600 apt-get \
    -o Acquire::Retries=3 \
    -o Dpkg::Options::=--force-confold \
    -o Dpkg::Use-Pty=0 \
    "$@"
}

# Retried rather than trusted. A runner can be holding the dpkg lock for its
# own unattended upgrade when the job starts, and the failure that produces is
# indistinguishable from a broken package list.
for attempt in 1 2 3; do
  if apt_get update -qq; then
    break
  fi
  if [ "$attempt" = 3 ]; then
    echo "apt-get update failed three times" >&2
    exit 1
  fi
  echo "apt-get update failed (attempt ${attempt}/3); waiting"
  sleep 10
done

# libdecor-0-dev is deliberately absent: GLFW uses it only to draw its own
# window decorations under Wayland and builds without it, so it is one more
# package that can be missing or can prompt, for nothing this program needs.
apt_get install -y --no-install-recommends \
  libgl1-mesa-dev \
  xorg-dev \
  libwayland-dev \
  libxkbcommon-dev \
  wayland-protocols
