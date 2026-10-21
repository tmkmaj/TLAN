#!/bin/sh
set -eu
ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT_DIR"
case "${1:-server}" in
  server) ;;
  *) echo "usage: $0 server" >&2; exit 2 ;;
esac
if [ -x "$ROOT_DIR/dist/linux/tmknetworklan-server" ]; then
  exec "$ROOT_DIR/dist/linux/tmknetworklan-server"
fi
command -v go >/dev/null 2>&1 || { echo "Go 1.23.1+ is required to build from source; the release binary runs directly" >&2; exit 1; }
mkdir -p "$ROOT_DIR/.bin"
go build -mod=vendor -trimpath -o "$ROOT_DIR/.bin/tmknetworklan-server" ./cmd/server
exec "$ROOT_DIR/.bin/tmknetworklan-server"
