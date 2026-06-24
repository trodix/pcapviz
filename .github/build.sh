#!/usr/bin/env bash
# Build all pcapviz release binaries into the given output directory.
# Usage: ./.github/build.sh <outdir>
#
# Assumes the frontend has already been built (web/ -> embedded dist) and that,
# for the Linux desktop binary, gcc + WebKitGTK 4.1 dev libraries are installed.
set -euo pipefail

OUT="${1:-out}"
mkdir -p "$OUT"

LDFLAGS="-s -w"

echo "==> web-server binaries (pure Go, static)"
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -ldflags "$LDFLAGS" -o "$OUT/pcapviz-linux-amd64"      ./cmd/pcapviz
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "$LDFLAGS" -o "$OUT/pcapviz-windows-amd64.exe" ./cmd/pcapviz

echo "==> desktop binary, Linux (cgo + WebKitGTK 4.1)"
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -ldflags "$LDFLAGS" -o "$OUT/pcapviz-desktop-linux-amd64" ./cmd/pcapviz-desktop

echo "==> desktop binary, Windows (go-webview2, pure Go, cross-compiled)"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "$LDFLAGS -H windowsgui" -o "$OUT/pcapviz-desktop-windows-amd64.exe" ./cmd/pcapviz-desktop

echo "==> done:"
ls -lh "$OUT"
