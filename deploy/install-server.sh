#!/bin/bash
# Build template: build-server-installer.ps1 appends a verified tar.gz payload.
# Compatible with Bash 4.2 and systemd 219 (CentOS 7.9).
set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
CHECK=0 REPLACE_CADDY=0 SKIP_FIREWALL=0
for arg in "$@"; do
    case "$arg" in
        --check) CHECK=1 ;;
        --replace-caddy) REPLACE_CADDY=1 ;;
        --skip-firewall) SKIP_FIREWALL=1 ;;
        --help|-h)
            cat <<'HELP'
TLAN Linux amd64 installer (CentOS 7.9 / Debian / Ubuntu)
Usage: sudo bash TLAN-server-linux-amd64.run [OPTIONS]
  --check           Validate prerequisites and configuration without installing
  --replace-caddy   Stop/disable an existing caddy.service (config/data retained)
  --skip-firewall   Leave host firewall rules to the administrator
Endpoint: https://<your-server-host>:8443 ; STUN: <your-server-host>:3478
Cloud security group must allow TCP 80, TCP 8443, TCP 8444 and UDP 3478.
TCP 80 is required for automatic certificate issuance and renewal.
Exit: 0 ready/check passed; 1 failed; 2 installed, certificate pending;
      3 installed, firewall needs attention.
HELP
            exit 0 ;;
        *) printf 'Unknown option: %s\n' "$arg" >&2; exit 1 ;;
    esac
done
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '\n==> %s\n' "$*"; }
[[ $(id -u) == 0 ]] || die 'Run with sudo bash (including --check).'
[[ $(uname -m) == x86_64 ]] || die 'This installer supports x86_64/amd64 only.'
[[ -r /etc/os-release ]] || die '/etc/os-release is missing.'
# Read known fields without sourcing a file as root.
OS_ID=$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"')
OS_VERSION=$(sed -n 's/^VERSION_ID=//p' /etc/os-release | tr -d '"')
case "$OS_ID" in centos|debian|ubuntu|rhel|rocky|almalinux) ;; *) die "Unsupported distribution: $OS_ID" ;; esac
[[ $OS_ID != centos || ${OS_VERSION%%.*} -ge 7 ]] || die 'CentOS 7.9 or later is required.'
[[ -d /run/systemd/system ]] || die 'Boot this machine with systemd first.'
for cmd in systemctl tar gzip sha256sum tail awk sed tr mktemp install cp mv rm stat find \
           useradd groupadd getent id chown chmod runuser flock grep sleep; do
    command -v "$cmd" >/dev/null || die "Missing $cmd. Install prerequisites: CentOS: util-linux tar gzip coreutils shadow-utils; Debian/Ubuntu: util-linux tar gzip coreutils passwd."
done
SYSTEMD_VERSION=$(systemctl --version | awk 'NR==1 { print $2 }')
[[ $SYSTEMD_VERSION =~ ^[0-9]+$ && $SYSTEMD_VERSION -ge 219 ]] || die 'systemd 219 or newer is required.'
case "$(uname -r)" in 0.*|1.*|2.*|3.0.*|3.1.*) die 'Linux kernel 3.2 or newer is required.' ;; esac
[[ -s /etc/pki/tls/certs/ca-bundle.crt || -s /etc/ssl/certs/ca-certificates.crt ]] || die 'Install/update ca-certificates before continuing.'
if (( ! CHECK )); then
    exec 9>/run/lock/tlan-install.lock
    flock -n 9 || die 'Another installation is running.'
fi
WORK=$(mktemp -d /var/tmp/tlan-install.XXXXXXXX)
export XDG_DATA_HOME="$WORK/caddy-data" XDG_CONFIG_HOME="$WORK/caddy-config"
BACKUP='' TRANSACTION=0 COMMITTED=0
UNITS=(tlan.service tlan-https.service)
FILES=(/opt/tlan/tlan-server /opt/tlan/caddy /opt/tlan/Caddyfile /opt/tlan/tlan-graceful-restart.sh
       /etc/systemd/system/tlan.service /etc/systemd/system/tlan-https.service
       /var/lib/tlan/tlan-config.yml)
declare -a WAS_ACTIVE WAS_ENABLED
rollback() {
    log "Installation failed; restoring managed files and service states from $BACKUP"
    systemctl stop "${UNITS[@]}" >/dev/null 2>&1 || true
    local i path
    for i in "${!FILES[@]}"; do
        path=${FILES[$i]}
        if [[ -e $BACKUP/file-$i ]]; then
            rm -f -- "$path"
            cp -a -- "$BACKUP/file-$i" "$path" || printf 'RESTORE FAILED: %s\n' "$path" >&2
        else
            rm -f -- "$path"
        fi
    done
    systemctl daemon-reload || true
    for i in "${!UNITS[@]}"; do
        if [[ ${WAS_ENABLED[$i]} == enabled ]]; then
            systemctl enable "${UNITS[$i]}" >/dev/null 2>&1 || true
        else
            systemctl disable "${UNITS[$i]}" >/dev/null 2>&1 || true
        fi
        if [[ ${WAS_ACTIVE[$i]} == active || ${WAS_ACTIVE[$i]} == activating ]]; then systemctl start "${UNITS[$i]}" || true; fi
    done
    printf 'Member data is retained. Backup: %s\n' "$BACKUP" >&2
}
finish() {
    local rc=$?
    trap - EXIT INT TERM
    set +e
    if (( TRANSACTION && ! COMMITTED )); then rollback; fi
    # WORK is exclusively mktemp-created, never supplied by the caller.
    if [[ $WORK == /var/tmp/tlan-install.* && -d $WORK ]]; then rm -rf -- "$WORK"; fi
    exit "$rc"
}
trap finish EXIT
trap 'exit 1' INT TERM
log "Checking bundled payload on $OS_ID $OS_VERSION (systemd $SYSTEMD_VERSION)"
PAYLOAD_LINE=$(awk '/^__TLAN_PAYLOAD_BELOW__$/ {print NR + 1; exit}' "$0")
[[ -n $PAYLOAD_LINE ]] || die 'Payload is missing. Use the built .run file.'
tail -n +"$PAYLOAD_LINE" "$0" > "$WORK/payload.tar.gz"
printf '%s  %s\n' '@PAYLOAD_SHA256@' "$WORK/payload.tar.gz" | sha256sum -c - >/dev/null || die 'Payload checksum mismatch.'
tar -xzf "$WORK/payload.tar.gz" -C "$WORK" --no-same-owner
chmod 755 "$WORK/install-helper" "$WORK/tlan-server" "$WORK/caddy"
"$WORK/install-helper" verify-elf "$WORK/tlan-server" "$WORK/caddy" "$WORK/install-helper"
"$WORK/caddy" validate --config "$WORK/Caddyfile" --adapter caddyfile
# Refuse symlinks for all managed paths, including their ancestors.
safe_path() {
    local p=$1
    while [[ $p != / && $p != . ]]; do
        [[ ! -L $p ]] || die "Refusing managed symlink: $p"
        p=${p%/*}; [[ -n $p ]] || p=/
    done
}
for path in "${FILES[@]}" /var/lib/tlan-caddy /var/backups/tlan; do safe_path "$path"; done
for path in "${FILES[@]}"; do [[ ! -e $path || -f $path ]] || die "Managed target is not a regular file: $path"; done
DATA_DIR=$("$WORK/install-helper" prepare /var/lib/tlan/tlan-config.yml "$WORK/prepared.yml")
safe_path "$DATA_DIR/state.json"
# Additional listeners and disabled/custom STUN settings are preserved.
for name in tlan tlanhttps; do
    if id "$name" >/dev/null 2>&1; then
        [[ $(id -u "$name") != 0 ]] || die "Unsafe existing account: $name has UID 0."
    fi
done
if systemctl is-active --quiet caddy.service; then
    (( REPLACE_CADDY )) || die 'caddy.service is running. Use --replace-caddy only if it exclusively serves TLAN; otherwise deploy manually.'
fi
for unit in "${UNITS[@]}"; do
    enabled=$(systemctl is-enabled "$unit" 2>/dev/null || true)
    case "$enabled" in masked|masked-runtime|enabled-runtime|linked|linked-runtime) die "Unit $unit is $enabled; resolve this before installation." ;; esac
    for prefix in /etc /run /usr/lib; do
        [[ ! -d $prefix/systemd/system/$unit.d ]] || die "Existing $unit drop-ins require manual review."
    done
done
if (( CHECK )); then
    log 'Preflight passed. Existing service ports may remain occupied during this read-only check.'
    printf 'Install target: /opt/tlan\nState: %s\nRequired inbound: TCP 80, TCP 8443, TCP 8444, UDP 3478\n' "$DATA_DIR"
    exit 0
fi
log 'Preparing accounts and backing up existing deployment'
for name in tlan tlanhttps; do
    getent group "$name" >/dev/null || groupadd --system "$name"
    if ! id "$name" >/dev/null 2>&1; then
        useradd --system --gid "$name" --home-dir /nonexistent --shell /sbin/nologin "$name"
    fi
done
install -d -m 755 /opt/tlan
chown root:root /opt/tlan
install -d -m 750 /var/lib/tlan /var/lib/tlan-caddy
install -d -m 700 /var/backups/tlan
BACKUP=$(mktemp -d /var/backups/tlan/install-XXXXXXXX)
for i in "${!FILES[@]}"; do
    if [[ -e ${FILES[$i]} ]]; then cp -a -- "${FILES[$i]}" "$BACKUP/file-$i"; fi
    printf '%s\n' "${FILES[$i]}" >> "$BACKUP/paths.txt"
done
if (( REPLACE_CADDY )); then UNITS+=(caddy.service); fi
for i in "${!UNITS[@]}"; do
    WAS_ACTIVE[$i]=$(systemctl is-active "${UNITS[$i]}" 2>/dev/null || true)
    WAS_ENABLED[$i]=$(systemctl is-enabled "${UNITS[$i]}" 2>/dev/null || true)
    printf '%s %s %s\n' "${UNITS[$i]}" "${WAS_ACTIVE[$i]}" "${WAS_ENABLED[$i]}" >> "$BACKUP/services.txt"
done
TRANSACTION=1
for i in "${!UNITS[@]}"; do
    if [[ ${WAS_ACTIVE[$i]} == active || ${WAS_ACTIVE[$i]} == activating ]]; then systemctl stop "${UNITS[$i]}"; fi
done
"$WORK/install-helper" ports "$WORK/prepared.yml"
if [[ -e $DATA_DIR/state.json ]]; then cp -a -- "$DATA_DIR/state.json" "$BACKUP/state.json"; fi
log 'Installing services (CentOS 7 compatible systemd units)'
for name in tlan-server caddy; do
    install -m 755 "$WORK/$name" "/opt/tlan/$name.new"
    mv -f "/opt/tlan/$name.new" "/opt/tlan/$name"
done
install -m 644 "$WORK/Caddyfile" /opt/tlan/Caddyfile
install -m 755 "$WORK/tlan-graceful-restart.sh" /opt/tlan/tlan-graceful-restart.sh
install -m 644 "$WORK/tlan.service" /etc/systemd/system/tlan.service
install -m 644 "$WORK/tlan-https.service" /etc/systemd/system/tlan-https.service
install -o tlan -g tlan -m 600 "$WORK/prepared.yml" /var/lib/tlan/tlan-config.yml
# Only the application's private paths are owned by its service account.
install -d -m 750 "$DATA_DIR"
chown tlan:tlan /var/lib/tlan "$DATA_DIR"
if [[ -f $DATA_DIR/state.json ]]; then chown tlan:tlan "$DATA_DIR/state.json"; fi
chown tlanhttps:tlanhttps /var/lib/tlan-caddy
if command -v restorecon >/dev/null; then
    restorecon -R /opt/tlan /var/lib/tlan /var/lib/tlan-caddy /etc/systemd/system/tlan.service /etc/systemd/system/tlan-https.service
fi
"$WORK/install-helper" set-bind-capability /opt/tlan/caddy
runuser -u tlan -- test -r /var/lib/tlan/tlan-config.yml
runuser -u tlan -- test -w "$DATA_DIR"
install -d -m 755 /opt/tlan/docs /opt/tlan/licenses
install -m 644 "$WORK/INSTALL-LINUX.md" /opt/tlan/docs/INSTALL-LINUX.md
install -m 644 "$WORK/IP-DEPLOYMENT.md" /opt/tlan/docs/IP-DEPLOYMENT.md
install -m 644 "$WORK/licenses/"* /opt/tlan/licenses/
systemctl daemon-reload
systemctl enable tlan.service tlan-https.service
if (( REPLACE_CADDY )); then systemctl disable caddy.service; fi
systemctl start tlan.service
"$WORK/install-helper" probe http 20
systemctl start tlan-https.service
sleep 2
systemctl is-active --quiet tlan-https.service || die 'HTTPS gateway failed to start; inspect journalctl -u tlan-https.'
# The deployment is now installed. Certificate/firewall failures must not undo
# a working backend or reset newly registered member state.
COMMITTED=1
log 'Opening host firewall ports (cloud security groups must be configured separately)'
FIREWALL_OK=1
if (( SKIP_FIREWALL )); then
    printf 'Skipped host firewall changes as requested.\n'
elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    ZONES=$(firewall-cmd --get-active-zones | awk '/^[^ ]/ {print $1}') || FIREWALL_OK=0
    if [[ -z $ZONES ]]; then ZONES=$(firewall-cmd --get-default-zone) || FIREWALL_OK=0; fi
    [[ -n $ZONES ]] || FIREWALL_OK=0
    for zone in $ZONES; do
        for port in 80/tcp 8443/tcp 8444/tcp 3478/udp; do
            firewall-cmd --zone="$zone" --add-port="$port" || FIREWALL_OK=0
            firewall-cmd --permanent --zone="$zone" --add-port="$port" || FIREWALL_OK=0
        done
    done
elif command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
    for port in 80/tcp 8443/tcp 8444/tcp 3478/udp; do ufw allow "$port" || FIREWALL_OK=0; done
else
    printf 'No active firewalld/UFW detected; custom iptables/nftables rules are unchanged.\n'
fi
printf '\nInstalled: https://<your-server-host>:8443\nConfig (contains secrets): /var/lib/tlan/tlan-config.yml\nBackup: %s\n' "$BACKUP"
printf 'Share only network.join_code with clients. Never share security.admin_token.\n'
log 'Waiting up to 45 seconds for a trusted IP certificate'
HTTPS_OK=1
"$WORK/install-helper" probe https 45 || HTTPS_OK=0
if (( ! FIREWALL_OK )); then
    printf 'INSTALLED; host firewall update failed. Check TCP 80/8443/8444 and UDP 3478.\n' >&2
    exit 3
fi
if (( ! HTTPS_OK )); then
    printf 'INSTALLED; HTTPS is not ready yet. Caddy will retry certificate issuance automatically.\n' >&2
    printf 'Check cloud TCP 80/8443, outbound HTTPS/DNS, system clock and CA roots.\n' >&2
    printf 'Logs: journalctl -u tlan-https -n 100 --no-pager\n' >&2
    exit 2
fi
printf '\nREADY: backend and certificate-verified IP HTTPS health checks passed.\n'
printf 'External reachability still depends on cloud security groups and network rules.\n'
exit 0
__TLAN_PAYLOAD_BELOW__
