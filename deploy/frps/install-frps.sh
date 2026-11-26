#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'HELP'
TLAN independent FRPS installer
Usage: sudo bash install-frps.sh [OPTIONS]
  --start           Install, verify and start both FRPS services
  --skip-firewall   Do not add host firewall rules
  --help, -h        Show this help
Existing /etc/tlan-frp configuration and token files are never overwritten.
Required public ports: TCP 7000, UDP 7002, UDP 7003, TCP 18080-18083,
TCP 18443-18444, and TCP/UDP 60000-61000. TCP 7001 stays loopback-only.
HELP
}

START_NOW="false"
SKIP_FIREWALL="false"
for arg in "$@"; do
  case "$arg" in
    --start) START_NOW="true" ;;
    --skip-firewall) SKIP_FIREWALL="true" ;;
    --help|-h) usage; exit 0 ;;
    *) printf 'Unknown option: %s\n' "$arg" >&2; usage >&2; exit 1 ;;
  esac
done

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "请使用 root 或 sudo 运行此脚本。" >&2
  exit 1
fi

VERSION="0.71.1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="${SCRIPT_DIR}/frps"
CONFIG_DIR="/etc/tlan-frp"
DATA_DIR="/var/lib/tlan-frp"
DEST="/opt/tlan-frp/${VERSION}"

if [[ ! -f "${BINARY}" ]]; then
  echo "安装包缺少可执行的 frps 二进制：${BINARY}" >&2
  exit 1
fi

if ! getent group tlan-frp >/dev/null 2>&1; then
  groupadd --system tlan-frp
fi
if ! id -u tlan-frp >/dev/null 2>&1; then
  useradd --system --gid tlan-frp --home-dir "${DATA_DIR}" --no-create-home --shell /usr/sbin/nologin tlan-frp
fi

install -d -m 0755 -o root -g root /opt/tlan-frp "${DEST}"
install -d -m 0750 -o root -g tlan-frp "${CONFIG_DIR}"
install -d -m 0750 -o tlan-frp -g tlan-frp "${DATA_DIR}"
install -m 0755 -o root -g root "${BINARY}" "${DEST}/frps"
install -m 0644 -o root -g root "${SCRIPT_DIR}/manifest.json" "${DEST}/manifest.json"
install -d -m 0755 -o root -g root /opt/tlan-frp/licenses
install -m 0644 -o root -g root "${SCRIPT_DIR}/licenses/FRP-LICENSE.txt" /opt/tlan-frp/licenses/FRP-LICENSE.txt
install -m 0644 -o root -g root "${SCRIPT_DIR}/THIRD-PARTY-NOTICES.md" /opt/tlan-frp/THIRD-PARTY-NOTICES.md
if [[ -f "${SCRIPT_DIR}/docs/FRPS-DEPLOY.md" ]]; then
  install -d -m 0755 -o root -g root /opt/tlan-frp/docs
  install -m 0644 -o root -g root "${SCRIPT_DIR}/docs/FRPS-DEPLOY.md" /opt/tlan-frp/docs/FRPS-DEPLOY.md
fi

if [[ ! -f "${CONFIG_DIR}/frps.toml" ]]; then
  install -m 0640 -o root -g tlan-frp "${SCRIPT_DIR}/frps.toml.example" "${CONFIG_DIR}/frps.toml"
fi
if [[ ! -f "${CONFIG_DIR}/frps-wss.toml" ]]; then
  install -m 0640 -o root -g tlan-frp "${SCRIPT_DIR}/frps-wss.toml.example" "${CONFIG_DIR}/frps-wss.toml"
fi
if [[ ! -s "${CONFIG_DIR}/token" ]]; then
  umask 077
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32 > "${CONFIG_DIR}/token"
  else
    od -An -N32 -tx1 /dev/urandom | tr -d ' \n' > "${CONFIG_DIR}/token"
    printf '\n' >> "${CONFIG_DIR}/token"
  fi
  chown root:tlan-frp "${CONFIG_DIR}/token"
  chmod 0640 "${CONFIG_DIR}/token"
fi

config_value() {
  local file="$1" key="$2" key_re
  key_re=${key//./\\.}
  sed -n -E "s/^[[:space:]]*${key_re}[[:space:]]*=[[:space:]]*\"?([^\"#[:space:]]+)\"?[[:space:]]*(#.*)?$/\1/p" "$file" | tail -n 1
}

CAPABILITIES_OK="true"
check_capabilities() {
  local file="$1" label="$2"
  shift 2
  local spec key expected actual
  for spec in "$@"; do
    key=${spec%%:*}
    expected=${spec#*:}
    actual=$(config_value "$file" "$key")
    if [[ "$actual" != "$expected" ]]; then
      printf 'CONFIG MISMATCH: %s %s=%s, expected %s\n' "$label" "$key" "${actual:-<missing>}" "$expected" >&2
      CAPABILITIES_OK="false"
    fi
  done
}

check_capabilities "${CONFIG_DIR}/frps.toml" "main" \
  bindAddr:0.0.0.0 bindPort:7000 kcpBindPort:7002 quicBindPort:7003 \
  proxyBindAddr:0.0.0.0 vhostHTTPPort:18080 vhostHTTPSPort:18443 \
  tcpmuxHTTPConnectPort:18081 subDomainHost:frp.example.com \
  transport.tls.force:true
check_capabilities "${CONFIG_DIR}/frps-wss.toml" "wss" \
  bindAddr:127.0.0.1 bindPort:7001 proxyBindAddr:0.0.0.0 \
  vhostHTTPPort:18082 vhostHTTPSPort:18444 tcpmuxHTTPConnectPort:18083 \
  subDomainHost:frp.example.com transport.tls.force:false

"${DEST}/frps" verify -c "${CONFIG_DIR}/frps.toml"
"${DEST}/frps" verify -c "${CONFIG_DIR}/frps-wss.toml"

if [[ "${CAPABILITIES_OK}" != "true" ]]; then
  cat >&2 <<'WARN'
The existing /etc/tlan-frp configuration was retained and was not overwritten.
It is syntactically valid but does not match this release's fixed port/capability
matrix. Manually merge the missing values from frps.toml.example and
frps-wss.toml.example before starting FRPS.
WARN
fi

if [[ ! -f "${CONFIG_DIR}/server.crt" || ! -f "${CONFIG_DIR}/server.key" ]]; then
  echo "尚未安装 TLS 证书。请把服务器证书和私钥放到："
  echo "  ${CONFIG_DIR}/server.crt"
  echo "  ${CONFIG_DIR}/server.key"
  echo "证书需包含 FRP 域名/IP 的 SAN；私钥权限应为 root:tlan-frp 0640。"
fi

install -m 0644 -o root -g root "${SCRIPT_DIR}/tlan-frps.service" /etc/systemd/system/tlan-frps.service
install -m 0644 -o root -g root "${SCRIPT_DIR}/tlan-frps-wss.service" /etc/systemd/system/tlan-frps-wss.service
systemctl daemon-reload
systemctl enable tlan-frps.service tlan-frps-wss.service

FIREWALL_OK=1
if [[ "${SKIP_FIREWALL}" == "true" ]]; then
  printf 'Skipped host firewall changes as requested.\n'
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  ZONES=$(firewall-cmd --get-active-zones | awk '/^[^ ]/ {print $1}') || FIREWALL_OK=0
  if [[ -z ${ZONES:-} ]]; then ZONES=$(firewall-cmd --get-default-zone) || FIREWALL_OK=0; fi
  [[ -n ${ZONES:-} ]] || FIREWALL_OK=0
  for zone in ${ZONES:-}; do
    for port in 7000/tcp 18080/tcp 18081/tcp 18082/tcp 18083/tcp 18443/tcp 18444/tcp; do
      firewall-cmd --zone="$zone" --add-port="$port" || FIREWALL_OK=0
      firewall-cmd --permanent --zone="$zone" --add-port="$port" || FIREWALL_OK=0
    done
    for port in 7002/udp 7003/udp 60000-61000/tcp 60000-61000/udp; do
      firewall-cmd --zone="$zone" --add-port="$port" || FIREWALL_OK=0
      firewall-cmd --permanent --zone="$zone" --add-port="$port" || FIREWALL_OK=0
    done
  done
elif command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then
  for port in 7000/tcp 18080/tcp 18081/tcp 18082/tcp 18083/tcp 18443/tcp 18444/tcp 7002/udp 7003/udp 60000:61000/tcp 60000:61000/udp; do
    ufw allow "$port" || FIREWALL_OK=0
  done
else
  printf 'No active firewalld/UFW detected; custom iptables/nftables rules are unchanged.\n'
fi

if [[ "${START_NOW}" == "true" ]]; then
  if [[ "${CAPABILITIES_OK}" != "true" ]]; then
    echo "拒绝启动：现有 /etc 配置未满足固定端口矩阵，且安装器不会覆盖它。" >&2
    exit 1
  fi
  if [[ ! -f "${CONFIG_DIR}/server.crt" || ! -f "${CONFIG_DIR}/server.key" ]]; then
    echo "证书不完整，拒绝启动 FRPS。" >&2
    exit 1
  fi
  systemctl restart tlan-frps.service tlan-frps-wss.service
  systemctl --no-pager --full status tlan-frps.service tlan-frps-wss.service || true
else
  echo "安装完成。配置 TLS 证书后运行：systemctl start tlan-frps.service tlan-frps-wss.service"
fi

if (( ! FIREWALL_OK )); then
  echo "FRPS 已安装，但主机防火墙更新失败；请手动放行文档中的 TCP/UDP 端口。" >&2
  exit 3
fi

echo "FRPS public ports: TCP 7000; UDP 7002/7003; TCP 18080-18083; TCP 18443-18444; TCP/UDP 60000-61000."
echo "WSS loopback only: 127.0.0.1:7001 (do not expose it)."