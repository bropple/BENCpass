#!/bin/sh
# Locate Zen or Firefox. Sourced, not run: it sets BROWSER_BIN.
#
#   . "$(dirname "$0")/find-browser.sh"
#
# One copy because three scripts need it and they were each doing
# `command -v zen-browser || command -v firefox`, which finds nothing at all on
# macOS: applications there live inside a bundle and the executable is buried in
# Contents/MacOS, never on PATH.
#
# BROWSER_BIN in the environment always wins.

find_browser() {
  [ -n "${BROWSER_BIN:-}" ] && return 0

  # On PATH — the normal Linux case, and a Homebrew or MacPorts install.
  for name in zen-browser zen firefox firefox-developer-edition; do
    found=$(command -v "$name" 2>/dev/null) || continue
    BROWSER_BIN=$found
    return 0
  done

  # Bundles. Zen has shipped under more than one name; both are checked, and
  # ~/Applications covers a per-user install.
  for base in /Applications "$HOME/Applications"; do
    for app in "Zen Browser" "Zen" "Firefox Developer Edition" "Firefox"; do
      for exe in zen firefox; do
        candidate="$base/$app.app/Contents/MacOS/$exe"
        if [ -x "$candidate" ]; then
          BROWSER_BIN=$candidate
          return 0
        fi
      done
    done
  done

  # Linux installs that skip PATH — tarball drops and some packagers.
  for candidate in /opt/zen/zen /opt/zen-browser/zen /usr/lib/zen/zen \
                   /opt/firefox/firefox /usr/lib/firefox/firefox; do
    if [ -x "$candidate" ]; then
      BROWSER_BIN=$candidate
      return 0
    fi
  done

  return 1
}

if ! find_browser; then
  echo "No Zen or Firefox found." >&2
  echo "Looked on PATH, in /Applications and ~/Applications, and in /opt." >&2
  echo "Set BROWSER_BIN to the executable, e.g." >&2
  echo "  BROWSER_BIN='/Applications/Zen Browser.app/Contents/MacOS/zen' $0" >&2
  exit 1
fi

export BROWSER_BIN
