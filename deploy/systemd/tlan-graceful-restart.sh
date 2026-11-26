#!/usr/bin/env bash
# Start a replacement TLAN process before stopping the systemd unit.
# Both processes use SO_REUSEPORT; the old process closes its listener first and
# drains existing relay sessions for up to 30 seconds while the new one serves.
set -euo pipefail

SERVICE=tlan.service
BINARY=/opt/tlan/tlan-server
RUN_USER=tlan
WORKDIR=/var/lib/tlan

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
log() { printf '[tlan] %s\n' "$*"; }

[[ $(id -u) -eq 0 ]] || die 'run as root'
[[ -x $BINARY ]] || die "missing executable: $BINARY"
command -v systemctl >/dev/null || die 'systemctl is required'
command -v systemd-run >/dev/null || die 'systemd-run is required'
id "$RUN_USER" >/dev/null 2>&1 || die "missing service account: $RUN_USER"

if ! systemctl is-active --quiet "$SERVICE"; then
  log 'service is not active; starting normally'
  systemctl start "$SERVICE"
  systemctl is-active --quiet "$SERVICE" || die 'service failed to start'
  exit 0
fi

UNIT="tlan-upgrade-$(date +%s)"
log "starting replacement as $UNIT"
# Compatible with systemd 219+, using /bin/sh + runuser to set cwd and user.
systemd-run --unit="$UNIT" /bin/sh -c "cd '$WORKDIR' && exec /usr/sbin/runuser -u '$RUN_USER' -- '$BINARY'"

for _ in $(seq 1 20); do
  if systemctl is-active --quiet "$UNIT"; then
    break
  fi
  sleep 0.25
done

if ! systemctl is-active --quiet "$UNIT"; then
  journalctl -u "$UNIT" -n 50 --no-pager || true
  die "replacement unit did not remain active"
fi

log 'replacement is active; stopping old service to begin its drain'
systemctl stop "$SERVICE"
log 'starting managed service alongside the replacement'
systemctl start "$SERVICE"
for _ in $(seq 1 40); do
  if systemctl is-active --quiet "$SERVICE"; then
    break
  fi
  sleep 0.25
done
systemctl is-active --quiet "$SERVICE" || {
  journalctl -u "$SERVICE" -n 80 --no-pager || true
  die 'managed service failed during handover; replacement is still running'
}
