#!/bin/bash
# Exercises the real rollback function with isolated files and a fake systemctl.
set -Eeuo pipefail
TEMPLATE=${1:-deploy/install-server.sh}
TEST_DIR=$(mktemp -d)
trap 'rm -rf -- "$TEST_DIR"' EXIT
BACKUP=$TEST_DIR/backup
mkdir "$BACKUP"
FILES=("$TEST_DIR/existing" "$TEST_DIR/new")
UNITS=(tlan.service tlan-https.service caddy.service)
WAS_ACTIVE=(active inactive active)
WAS_ENABLED=(enabled disabled enabled)
printf 'original\n' > "$BACKUP/file-0"
printf 'replacement\n' > "${FILES[0]}"
printf 'new file\n' > "${FILES[1]}"
systemctl() { printf '%s\n' "$*" >> "$TEST_DIR/systemctl.log"; }
log() { :; }
source <(sed -n '/^rollback() {$/,/^}$/p' "$TEMPLATE")
rollback
[[ $(cat "${FILES[0]}") == original ]]
[[ ! -e ${FILES[1]} ]]
grep -Fxq 'enable tlan.service' "$TEST_DIR/systemctl.log"
grep -Fxq 'start tlan.service' "$TEST_DIR/systemctl.log"
grep -Fxq 'disable tlan-https.service' "$TEST_DIR/systemctl.log"
! grep -Fxq 'start tlan-https.service' "$TEST_DIR/systemctl.log"
grep -Fxq 'enable caddy.service' "$TEST_DIR/systemctl.log"
grep -Fxq 'start caddy.service' "$TEST_DIR/systemctl.log"
printf 'PASS: rollback restores files, removes new files, and restores service states.\n'
