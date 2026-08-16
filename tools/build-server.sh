#!/bin/sh
# Cross-compile bencpass-server and prove each binary is self-contained.
#
# Following benco-build-and-packaging.md: assert it, never assume it. A Go
# binary built with CGO_ENABLED=0 is static, but the flag is one environment
# variable away from being lost, and the failure lands on the NAS as a container
# that exits immediately with no message worth reading.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
out="$root/dist/server"
version=${VERSION:-dev}

mkdir -p "$out"

for target in linux/amd64 linux/arm64 darwin/arm64 windows/amd64; do
  goos=${target%%/*}
  goarch=${target##*/}
  name="bencpass-server-$goos-$goarch"
  [ "$goos" = "windows" ] && name="$name.exe"

  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -C "$root/server" -trimpath -ldflags="-s -w -X main.version=$version" \
    -o "$out/$name" .

  size=$(stat -c%s "$out/$name" 2>/dev/null || stat -f%z "$out/$name")
  printf '%-38s %8s bytes  ' "$name" "$size"

  # The check, per platform. A dynamic executable here means CGO_ENABLED was not
  # honoured, and the artefact is not the one this script claims to produce.
  case "$goos" in
    linux)
      if file -b "$out/$name" | grep -q 'dynamically linked'; then
        echo "FAIL: dynamically linked"
        exit 1
      fi
      ;;
    darwin)
      # Every Mach-O links libSystem; what must not appear is anything else.
      if command -v otool >/dev/null 2>&1 && otool -L "$out/$name" | grep -qv 'libSystem\|:$'; then
        echo "FAIL: unexpected dynamic dependency"
        exit 1
      fi
      ;;
  esac
  echo "static"
done

echo
echo "wrote $out"
