#!/usr/bin/env bash
#
# TLAN Linux One-Click Installer
# Automatically installs missing dependencies, prompts for admin key & settings,
# builds/installs tlan-server + Caddy HTTPS gateway, and configures systemd.
#
set -Eeuo pipefail

APP_NAME="TLAN"
INSTALL_DIR="/opt/tlan"
DATA_DIR="/var/lib/tlan"
CONFIG_FILE="${DATA_DIR}/tlan-config.yml"
SERVICE_USER="tlan"
HTTPS_USER="tlanhttps"
CADDY_STATE_DIR="/var/lib/tlan-caddy"
SYSTEMD_DIR="/etc/systemd/system"
MIN_GO_VERSION="1.23.1"
DEFAULT_GO_DOWNLOAD_VER="1.24.2"
GO_SHA256_AMD64="68097bd680839cbc9d464a0edce4f7c333975e27a90246890e9f1078c7e702ad"
GO_SHA256_ARM64="756274ea4b68fa5535eb9fe2559889287d725a8da63c6aae4d5f23778c229f4b"
DEFAULT_CADDY_VER="2.11.7"
CADDY_SHA512_AMD64="a7a433a1b133efc3c8d10eb0b99d52a24b5ef5c322dc77f5282182b1c0402139ab83f3a99f0c52409df77d20123fb0b523edad8a66d8f5e49136197bf61ef0e7"
CADDY_SHA512_ARM64="3db36ba90c7a6e8dda40ee3dd71fa08844c76b5fb08f61b31e5e78d2ed38e71c51dc7baed875e50d1ca1279196e84302967237386ae87c91ae9f2aaceada682e"

ADMIN_TOKEN="${TLAN_ADMIN_TOKEN:-}"
JOIN_CODE="${TLAN_JOIN_CODE:-}"
NETWORK_NAME="${TLAN_NETWORK_NAME:-TLAN}"
NETWORK_CIDR="${TLAN_CIDR:-10.240.0.0/24}"
PUBLIC_HOST="${TLAN_PUBLIC_HOST:-}"
CONTROL_PORT="${TLAN_CONTROL_PORT:-8080}"
HTTPS_PORT="${TLAN_HTTPS_PORT:-8443}"
ADMIN_PORT="${TLAN_ADMIN_PORT:-8081}"
ADMIN_HTTPS_PORT="${TLAN_ADMIN_HTTPS_PORT:-8444}"
STUN_PORT="${TLAN_STUN_PORT:-3478}"
BINARY_PATH="${TLAN_BINARY_PATH:-}"
REPO_URL="${TLAN_REPO_URL:-}"
NO_CADDY=0
ALLOW_INSECURE_PUBLIC_CONTROL=0
SKIP_FIREWALL=0
NON_INTERACTIVE=0
RECONFIGURE=0
KEEP_EXISTING_CONFIG=0
UNINSTALL=0
CHECK_ONLY=0

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

log()  { printf '[TLAN] %s\n' "$*"; }
warn() { printf '[TLAN WARN] %s\n' "$*" >&2; }
die()  { printf '[TLAN ERROR] %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
TLAN Linux One-Click Server Installer

Usage:
  sudo bash install.sh [OPTIONS]

Options:
  --admin-token <TOKEN>    Set the server Admin Token (required for admin console & admin client mode)
  --join-code <CODE>       Set the network Join Code for members (random if left blank)
  --network-name <NAME>    Virtual LAN display name (default: TLAN)
  --cidr <CIDR>            Virtual subnet CIDR (default: 10.240.0.0/24)
  --host <IP_OR_DOMAIN>    Server public IP or domain name (auto-detected if omitted)
  --https-port <PORT>      Public Caddy HTTPS port (default: 8443)
  --admin-https-port <P>   Public Caddy Admin HTTPS port (default: 8444)
  --stun-port <PORT>       UDP STUN port (default: 3478)
  --binary <PATH>          Use an existing compiled tlan-server Linux binary instead of building
  --repo-url <URL>         Git repository URL when running install.sh standalone outside repo
  --no-caddy               Do not install/configure Caddy HTTPS proxy (run HTTP on 127.0.0.1:8080)
  --allow-insecure-public-control
                           With --no-caddy, bind HTTP control listener to 0.0.0.0 and open firewall port (unsafe on public networks)
  --skip-firewall          Do not modify ufw / firewalld rules
  --reconfigure            Overwrite existing tlan-config.yml (backs up previous config first)
  --non-interactive        Fail instead of prompting if required fields are missing (unless auto-generated)
  --check                  Verify OS, architecture, systemd, and port prerequisites only
  --uninstall              Stop and disable systemd services (keeps data unless manually removed)
  -h, --help               Show this help message

Environment variables:
  TLAN_ADMIN_TOKEN, TLAN_JOIN_CODE, TLAN_NETWORK_NAME, TLAN_CIDR,
  TLAN_PUBLIC_HOST, TLAN_HTTPS_PORT, TLAN_STUN_PORT, TLAN_BINARY_PATH, TLAN_REPO_URL
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --admin-token)       [[ $# -ge 2 ]] || die "--admin-token requires a value"; ADMIN_TOKEN="$2"; shift 2 ;;
      --join-code)         [[ $# -ge 2 ]] || die "--join-code requires a value"; JOIN_CODE="$2"; shift 2 ;;
      --network-name)      [[ $# -ge 2 ]] || die "--network-name requires a value"; NETWORK_NAME="$2"; shift 2 ;;
      --cidr)              [[ $# -ge 2 ]] || die "--cidr requires a value"; NETWORK_CIDR="$2"; shift 2 ;;
      --host)              [[ $# -ge 2 ]] || die "--host requires a value"; PUBLIC_HOST="$2"; shift 2 ;;
      --https-port)        [[ $# -ge 2 ]] || die "--https-port requires a value"; HTTPS_PORT="$2"; shift 2 ;;
      --admin-https-port)  [[ $# -ge 2 ]] || die "--admin-https-port requires a value"; ADMIN_HTTPS_PORT="$2"; shift 2 ;;
      --stun-port)         [[ $# -ge 2 ]] || die "--stun-port requires a value"; STUN_PORT="$2"; shift 2 ;;
      --binary)            [[ $# -ge 2 ]] || die "--binary requires a value"; BINARY_PATH="$2"; shift 2 ;;
      --repo-url)          [[ $# -ge 2 ]] || die "--repo-url requires a value"; REPO_URL="$2"; shift 2 ;;
      --no-caddy)          NO_CADDY=1; shift ;;
      --allow-insecure-public-control) ALLOW_INSECURE_PUBLIC_CONTROL=1; shift ;;
      --skip-firewall)     SKIP_FIREWALL=1; shift ;;
      --reconfigure)       RECONFIGURE=1; shift ;;
      --non-interactive)   NON_INTERACTIVE=1; shift ;;
      --check)             CHECK_ONLY=1; shift ;;
      --uninstall)         UNINSTALL=1; shift ;;
      -h|--help)           usage; exit 0 ;;
      *)                   die "Unknown option: $1 (use --help for usage)" ;;
    esac
  done
}

detect_os_and_arch() {
  local uname_s uname_m
  uname_s="$(uname -s)"
  [[ "$uname_s" == "Linux" ]] || die "Unsupported operating system: ${uname_s}. This installer only supports Linux."

  uname_m="$(uname -m)"
  case "$uname_m" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) die "Unsupported CPU architecture: ${uname_m}. Supported architectures: x86_64 (amd64), aarch64 (arm64)." ;;
  esac

  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_LIKE="${ID_LIKE:-}"
    OS_PRETTY="${PRETTY_NAME:-$OS_ID}"
  else
    die "Cannot detect Linux distribution (/etc/os-release missing). Unsupported environment."
  fi

  if command -v apt-get >/dev/null 2>&1; then
    PKG_MGR="apt"
  elif command -v dnf >/dev/null 2>&1; then
    PKG_MGR="dnf"
  elif command -v yum >/dev/null 2>&1; then
    PKG_MGR="yum"
  else
    die "No supported package manager found (apt-get, dnf, or yum required) on ${OS_PRETTY}. Cannot automatically install dependencies."
  fi

  command -v systemctl >/dev/null 2>&1 || die "systemctl not found. A systemd-based Linux distribution is required."
  if [[ ! -d /run/systemd/system ]]; then
    die "systemd is not active as PID 1 on this host (container or chroot without systemd?). Cannot configure systemctl services."
  fi
}

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    die "This script must run as root. Re-run with: sudo bash $0 $*"
  fi
}

validate_port() {
  local name="$1" val="$2"
  [[ "$val" =~ ^[0-9]+$ ]] && (( val >= 1 && val <= 65535 )) || die "Invalid ${name}: '${val}' (must be 1-65535)"
}

validate_yaml_safe_scalar() {
  local name="$1" val="$2"
  if [[ -z "$val" ]]; then
    die "${name} cannot be empty."
  fi
  if [[ "$val" =~ [[:cntrl:]] ]]; then
    die "${name} contains invalid control characters."
  fi
  if [[ "$val" == *\"* || "$val" == *\'* || "$val" == *\\* ]]; then
    die "${name} cannot contain quotes or backslashes."
  fi
}

version_ge() {
  # Returns 0 if $1 >= $2 (semver comparison)
  local v1="$1" v2="$2"
  printf '%s\n%s\n' "$v2" "$v1" | sort -V -C
}

pkg_install() {
  local pkgs=("$@")
  [[ ${#pkgs[@]} -gt 0 ]] || return 0
  log "Installing missing packages (${PKG_MGR}): ${pkgs[*]}"
  case "$PKG_MGR" in
    apt)
      DEBIAN_FRONTEND=noninteractive apt-get update -qq || die "apt-get update failed; check network/repositories."
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${pkgs[@]}" || die "apt-get install failed for: ${pkgs[*]}"
      ;;
    dnf)
      dnf install -y -q "${pkgs[@]}" || die "dnf install failed for: ${pkgs[*]}"
      ;;
    yum)
      yum install -y -q "${pkgs[@]}" || die "yum install failed for: ${pkgs[*]}"
      ;;
  esac
}

ensure_base_tools() {
  local missing=()
  command -v curl >/dev/null 2>&1 || missing+=(curl)
  command -v tar >/dev/null 2>&1 || missing+=(tar)
  command -v gzip >/dev/null 2>&1 || missing+=(gzip)
  command -v openssl >/dev/null 2>&1 || missing+=(openssl)
  command -v setcap >/dev/null 2>&1 || {
    if [[ "$PKG_MGR" == "apt" ]]; then missing+=(libcap2-bin); else missing+=(libcap); fi
  }
  if [[ "$PKG_MGR" == "apt" ]]; then
    dpkg -s ca-certificates >/dev/null 2>&1 || missing+=(ca-certificates)
  else
    rpm -q ca-certificates >/dev/null 2>&1 || missing+=(ca-certificates)
  fi
  if [[ ${#missing[@]} -gt 0 ]]; then
    pkg_install "${missing[@]}"
  fi
  for cmd in curl tar gzip openssl setcap; do
    command -v "$cmd" >/dev/null 2>&1 || die "Required tool '${cmd}' is still missing after package installation."
  done
}

find_source_dir() {
  if [[ -f "${SCRIPT_DIR}/go.mod" && -d "${SCRIPT_DIR}/cmd/server" ]]; then
    printf '%s\n' "$SCRIPT_DIR"
    return 0
  fi
  return 1
}

verify_sha256() {
  local file="$1" expected="$2" actual=""
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$file" | awk '{print tolower($1)}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$file" | awk '{print tolower($1)}')"
  else
    actual="$(openssl dgst -sha256 "$file" | awk '{print tolower($NF)}')"
  fi
  [[ "$actual" == "$expected" ]] || die "SHA-256 mismatch for ${file}: got ${actual}, expected ${expected}"
}

verify_sha512() {
  local file="$1" expected="$2" actual=""
  if command -v sha512sum >/dev/null 2>&1; then
    actual="$(sha512sum "$file" | awk '{print tolower($1)}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 512 "$file" | awk '{print tolower($1)}')"
  else
    actual="$(openssl dgst -sha512 "$file" | awk '{print tolower($NF)}')"
  fi
  [[ "$actual" == "$expected" ]] || die "SHA-512 mismatch for ${file}: got ${actual}, expected ${expected}"
}

ensure_go_toolchain() {
  local current_ver=""
  if command -v go >/dev/null 2>&1; then
    current_ver="$(go version 2>/dev/null | sed -nE 's/^go version go([0-9]+\.[0-9]+(\.[0-9]+)?).*/\1/p')"
  fi
  if [[ -x /usr/local/go/bin/go && -z "$current_ver" ]]; then
    export PATH="/usr/local/go/bin:${PATH}"
    current_ver="$(go version 2>/dev/null | sed -nE 's/^go version go([0-9]+\.[0-9]+(\.[0-9]+)?).*/\1/p')"
  fi
  if [[ -n "$current_ver" ]] && version_ge "$current_ver" "$MIN_GO_VERSION"; then
    log "Go ${current_ver} detected (>= ${MIN_GO_VERSION})."
    return 0
  fi

  log "Installing Go ${DEFAULT_GO_DOWNLOAD_VER} (linux/${ARCH}) because installed Go ('${current_ver:-none}') is missing or older than ${MIN_GO_VERSION}..."
  local tmp_dir tmp_tgz url expected_sha256
  tmp_dir="$(mktemp -d /tmp/go-download.XXXXXX)"
  tmp_tgz="${tmp_dir}/go.tar.gz"
  url="https://go.dev/dl/go${DEFAULT_GO_DOWNLOAD_VER}.linux-${ARCH}.tar.gz"
  if [[ "$ARCH" == "amd64" ]]; then expected_sha256="$GO_SHA256_AMD64"; else expected_sha256="$GO_SHA256_ARM64"; fi
  if ! curl -fsSL --retry 3 --connect-timeout 15 "$url" -o "$tmp_tgz"; then
    rm -rf "$tmp_dir"
    die "Failed to download Go from ${url}. Install Go >= ${MIN_GO_VERSION} manually or pass --binary <path>."
  fi
  verify_sha256 "$tmp_tgz" "$expected_sha256"
  tar -C "$tmp_dir" -xzf "$tmp_tgz" || {
    rm -rf "$tmp_dir"
    die "Failed to extract Go tarball."
  }
  [[ -x "${tmp_dir}/go/bin/go" ]] || {
    rm -rf "$tmp_dir"
    die "Extracted Go archive does not contain go/bin/go."
  }
  rm -rf /usr/local/go
  mv "${tmp_dir}/go" /usr/local/go
  rm -rf "$tmp_dir"
  export PATH="/usr/local/go/bin:${PATH}"
  ln -sf /usr/local/go/bin/go /usr/local/bin/go || true
  command -v go >/dev/null 2>&1 || die "Go installation succeeded but 'go' binary is not executable."
  log "Installed $(go version)."
}

ensure_caddy() {
  if (( NO_CADDY )); then
    return 0
  fi
  if [[ -x "${INSTALL_DIR}/caddy" ]]; then
    log "Using existing Caddy at ${INSTALL_DIR}/caddy."
    return 0
  fi
  if command -v caddy >/dev/null 2>&1; then
    local existing_caddy
    existing_caddy="$(command -v caddy)"
    cp -f "$existing_caddy" "${INSTALL_DIR}/caddy"
    chmod 0755 "${INSTALL_DIR}/caddy"
    log "Copied system Caddy (${existing_caddy}) to ${INSTALL_DIR}/caddy."
    return 0
  fi

  log "Downloading Caddy v${DEFAULT_CADDY_VER} (linux/${ARCH})..."
  local tmp_dir url tar_file expected_sha512
  tmp_dir="$(mktemp -d /tmp/tlan-caddy.XXXXXX)"
  tar_file="${tmp_dir}/caddy.tar.gz"
  url="https://github.com/caddyserver/caddy/releases/download/v${DEFAULT_CADDY_VER}/caddy_${DEFAULT_CADDY_VER}_linux_${ARCH}.tar.gz"
  if [[ "$ARCH" == "amd64" ]]; then expected_sha512="$CADDY_SHA512_AMD64"; else expected_sha512="$CADDY_SHA512_ARM64"; fi
  if ! curl -fsSL --retry 3 --connect-timeout 15 "$url" -o "$tar_file"; then
    rm -rf "$tmp_dir"
    die "Failed to download Caddy from ${url}. Check internet access, pre-install caddy, or pass --no-caddy."
  fi
  verify_sha512 "$tar_file" "$expected_sha512"
  tar -xzf "$tar_file" -C "$tmp_dir" caddy || {
    rm -rf "$tmp_dir"
    die "Failed to extract Caddy binary from downloaded archive."
  }
  install -m 0755 "${tmp_dir}/caddy" "${INSTALL_DIR}/caddy"
  rm -rf "$tmp_dir"
  log "Installed Caddy v${DEFAULT_CADDY_VER} to ${INSTALL_DIR}/caddy."
}

detect_default_host() {
  local detected=""
  detected="$(curl -fsS --max-time 3 https://api.ipify.org 2>/dev/null || true)"
  if [[ -z "$detected" ]]; then
    detected="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  fi
  printf '%s' "$detected"
}

random_hex() {
  local bytes="$1"
  openssl rand -hex "$bytes"
}

prompt_line() {
  local prompt_msg="$1" default_val="$2" var_name="$3" silent="${4:-0}"
  local input=""
  if (( NON_INTERACTIVE )) || [[ ! -r /dev/tty ]]; then
    printf -v "$var_name" '%s' "$default_val"
    return 0
  fi
  if (( silent )); then
    printf '%s' "$prompt_msg" >/dev/tty
    IFS= read -r -s input </dev/tty || true
    printf '\n' >/dev/tty
  else
    if [[ -n "$default_val" ]]; then
      printf '%s [%s]: ' "$prompt_msg" "$default_val" >/dev/tty
    else
      printf '%s: ' "$prompt_msg" >/dev/tty
    fi
    IFS= read -r input </dev/tty || true
  fi
  if [[ -z "$input" ]]; then
    input="$default_val"
  fi
  printf -v "$var_name" '%s' "$input"
}

collect_user_config() {
  local existing_cfg=0
  if [[ -f "$CONFIG_FILE" && "$RECONFIGURE" -eq 0 ]]; then
    existing_cfg=1
    KEEP_EXISTING_CONFIG=1
    log "Existing configuration found at ${CONFIG_FILE}; keeping existing secrets/settings (pass --reconfigure to overwrite)."
    return 0
  fi

  local suggested_host
  suggested_host="$(detect_default_host)"
  if [[ -z "$PUBLIC_HOST" ]]; then
    prompt_line "Public IP or domain name for Caddy TLS/endpoint" "$suggested_host" PUBLIC_HOST 0
  fi

  if [[ -z "$ADMIN_TOKEN" ]]; then
    if (( NON_INTERACTIVE )); then
      die "--admin-token (or TLAN_ADMIN_TOKEN) is required in --non-interactive mode."
    fi
    while [[ -z "$ADMIN_TOKEN" ]]; do
      local generated_hint
      generated_hint="$(random_hex 16)"
      printf 'Enter your Admin Token (press Enter to auto-generate: %s): ' "$generated_hint" >/dev/tty 2>/dev/null || true
      if [[ -r /dev/tty ]]; then
        IFS= read -r -s ADMIN_TOKEN </dev/tty || true
        printf '\n' >/dev/tty
      else
        die "Cannot read Admin Token interactively. Pass --admin-token <TOKEN>."
      fi
      if [[ -z "$ADMIN_TOKEN" ]]; then
        ADMIN_TOKEN="$generated_hint"
        log "Generated Admin Token automatically."
      fi
      if (( ${#ADMIN_TOKEN} < 8 )); then
        warn "Admin Token is too short (minimum 8 characters recommended). Please try again."
        ADMIN_TOKEN=""
      fi
    done
  fi
  validate_yaml_safe_scalar "Admin Token" "$ADMIN_TOKEN"

  if [[ -z "$JOIN_CODE" ]]; then
    local default_join
    default_join="$(random_hex 8)"
    prompt_line "Member Join Code (press Enter to use generated code)" "$default_join" JOIN_CODE 0
  fi
  validate_yaml_safe_scalar "Join Code" "$JOIN_CODE"

  prompt_line "Virtual Network Name" "$NETWORK_NAME" NETWORK_NAME 0
  validate_yaml_safe_scalar "Network Name" "$NETWORK_NAME"

  prompt_line "Virtual Subnet CIDR" "$NETWORK_CIDR" NETWORK_CIDR 0
  validate_yaml_safe_scalar "Network CIDR" "$NETWORK_CIDR"

  return $existing_cfg
}

build_or_install_binary() {
  install -d -m 0755 "$INSTALL_DIR"
  if [[ -n "$BINARY_PATH" ]]; then
    [[ -f "$BINARY_PATH" ]] || die "Specified binary not found: ${BINARY_PATH}"
    install -m 0755 "$BINARY_PATH" "${INSTALL_DIR}/tlan-server.new"
    mv -f "${INSTALL_DIR}/tlan-server.new" "${INSTALL_DIR}/tlan-server"
    log "Installed prebuilt server binary from ${BINARY_PATH}."
    return 0
  fi

  local src_dir="" temp_clone=""
  if src_dir="$(find_source_dir)"; then
    log "Building tlan-server from local repository (${src_dir})..."
  else
    [[ -n "$REPO_URL" ]] || die "Not inside a TLAN source tree and no --binary / --repo-url provided. Clone the repository first or pass --binary /path/to/tlan-server."
    if ! command -v git >/dev/null 2>&1; then
      pkg_install git
    fi
    temp_clone="$(mktemp -d /tmp/tlan-src.XXXXXX)"
    log "Cloning source from ${REPO_URL}..."
    git clone --depth 1 "$REPO_URL" "$temp_clone" || {
      rm -rf "$temp_clone"
      die "git clone failed for ${REPO_URL}"
    }
    src_dir="$temp_clone"
  fi

  ensure_go_toolchain
  local mod_flag=""
  if [[ -d "${src_dir}/vendor" ]]; then
    mod_flag="-mod=vendor"
  fi
  (
    cd "$src_dir"
    CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build $mod_flag -ldflags '-s -w' -o "${INSTALL_DIR}/tlan-server.new" ./cmd/server
  ) || {
    [[ -n "$temp_clone" ]] && rm -rf "$temp_clone"
    die "Failed to build tlan-server with Go."
  }
  [[ -n "$temp_clone" ]] && rm -rf "$temp_clone"
  chmod 0755 "${INSTALL_DIR}/tlan-server.new"
  mv -f "${INSTALL_DIR}/tlan-server.new" "${INSTALL_DIR}/tlan-server"
  log "Built and installed ${INSTALL_DIR}/tlan-server."
}

ensure_accounts_and_dirs() {
  local nologin_shell="/usr/sbin/nologin"
  [[ -x "$nologin_shell" ]] || nologin_shell="/sbin/nologin"
  [[ -x "$nologin_shell" ]] || nologin_shell="/bin/false"

  for acct in "$SERVICE_USER" "$HTTPS_USER"; do
    if ! id "$acct" >/dev/null 2>&1; then
      if command -v useradd >/dev/null 2>&1; then
        useradd --system --home-dir "$DATA_DIR" --no-create-home --shell "$nologin_shell" "$acct" || die "Failed to create system user ${acct}"
      else
        adduser --system --no-create-home --shell "$nologin_shell" "$acct" || die "Failed to create system user ${acct}"
      fi
    fi
  done

  install -d -m 0750 "$DATA_DIR" "${DATA_DIR}/data"
  chown -R "${SERVICE_USER}:${SERVICE_USER}" "$DATA_DIR"
  install -d -m 0750 "$CADDY_STATE_DIR"
  chown -R "${HTTPS_USER}:${HTTPS_USER}" "$CADDY_STATE_DIR"
}

write_server_config() {
  if [[ -f "$CONFIG_FILE" && "$RECONFIGURE" -eq 0 ]]; then
    chown "${SERVICE_USER}:${SERVICE_USER}" "$CONFIG_FILE"
    chmod 0600 "$CONFIG_FILE"
    return 0
  fi

  if [[ -f "$CONFIG_FILE" ]]; then
    local backup_path="${CONFIG_FILE}.bak.$(date +%Y%m%d%H%M%S)"
    cp -a "$CONFIG_FILE" "$backup_path"
    chmod 0600 "$backup_path"
    log "Backed up existing configuration to ${backup_path}"
  fi

  local control_listen="127.0.0.1:${CONTROL_PORT}"
  if (( NO_CADDY && ALLOW_INSECURE_PUBLIC_CONTROL )); then
    control_listen="0.0.0.0:${CONTROL_PORT}"
  fi

  local tmp_cfg
  tmp_cfg="$(mktemp "${DATA_DIR}/.tlan-config.XXXXXX")"
  cat >"$tmp_cfg" <<EOF
# TLAN Server Configuration (generated by install.sh)
network:
  name: "${NETWORK_NAME}"
  cidr: "${NETWORK_CIDR}"
  join_code: "${JOIN_CODE}"
server:
  listen: "${control_listen}"
  stun_listen: ":${STUN_PORT}"
  admin_listen: "127.0.0.1:${ADMIN_PORT}"
  admin_tls_cert: ""
  admin_tls_key: ""
  admin_allow_insecure_http: false
  tls_cert: ""
  tls_key: ""
  min_client_version: ""
  relay_listen: ""
  relay_cert: ""
  relay_key: ""
  relay_queue_depth: 128
storage:
  data_dir: "${DATA_DIR}/data"
security:
  admin_token: "${ADMIN_TOKEN}"
frp:
  mode: "disabled"
  core_version: "0.71.1"
EOF
  chown "${SERVICE_USER}:${SERVICE_USER}" "$tmp_cfg"
  chmod 0600 "$tmp_cfg"
  mv -f "$tmp_cfg" "$CONFIG_FILE"
  log "Wrote server config to ${CONFIG_FILE} (mode 0600)."
}

write_caddyfile_and_units() {
  cat >"${SYSTEMD_DIR}/tlan.service" <<EOF
[Unit]
Description=TLAN Private LAN Control & Relay Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${DATA_DIR}
ExecStart=${INSTALL_DIR}/tlan-server -config ${CONFIG_FILE}
Restart=on-failure
RestartSec=3
LimitNOFILE=65536
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

  if (( ! NO_CADDY )); then
    if (( KEEP_EXISTING_CONFIG )) && [[ -f "${INSTALL_DIR}/Caddyfile" ]] && [[ -z "$PUBLIC_HOST" ]]; then
      log "Keeping existing ${INSTALL_DIR}/Caddyfile (pass --reconfigure or --host to regenerate)."
    else
      if [[ -f "${INSTALL_DIR}/Caddyfile" ]]; then
        local caddy_bak="${INSTALL_DIR}/Caddyfile.bak.$(date +%Y%m%d%H%M%S)"
        cp -a "${INSTALL_DIR}/Caddyfile" "$caddy_bak"
        chmod 0644 "$caddy_bak"
        log "Backed up existing Caddyfile to ${caddy_bak}"
      fi
      local tls_directive="tls internal"
      local site_host="${PUBLIC_HOST}"
      if [[ -n "$site_host" && ! "$site_host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ && "$site_host" != *:* ]]; then
        # Public DNS domain: let Caddy obtain Let's Encrypt or keep internal if unreachable.
        tls_directive=""
      fi

      cat >"${INSTALL_DIR}/Caddyfile" <<EOF
# TLAN Caddy HTTPS Gateway
# If using an IP address, clients can install the Caddy local root CA:
#   ${CADDY_STATE_DIR}/.local/share/caddy/pki/authorities/local/root.crt

${site_host}:${HTTPS_PORT} {
${tls_directive:+	${tls_directive}}
	reverse_proxy 127.0.0.1:${CONTROL_PORT} {
		flush_interval -1
	}
}

${site_host}:${ADMIN_HTTPS_PORT} {
${tls_directive:+	${tls_directive}}
	reverse_proxy 127.0.0.1:${ADMIN_PORT}
}
EOF
      chmod 0644 "${INSTALL_DIR}/Caddyfile"
    fi
    setcap 'cap_net_bind_service=+ep' "${INSTALL_DIR}/caddy" || warn "Failed to apply cap_net_bind_service to Caddy"

    cat >"${SYSTEMD_DIR}/tlan-https.service" <<EOF
[Unit]
Description=TLAN Caddy HTTPS Gateway
After=network-online.target tlan.service
Wants=network-online.target tlan.service

[Service]
Type=simple
User=${HTTPS_USER}
Group=${HTTPS_USER}
WorkingDirectory=${CADDY_STATE_DIR}
Environment=HOME=${CADDY_STATE_DIR}
Environment=XDG_DATA_HOME=${CADDY_STATE_DIR}/.local/share
Environment=XDG_CONFIG_HOME=${CADDY_STATE_DIR}/.config
ExecStart=${INSTALL_DIR}/caddy run --config ${INSTALL_DIR}/Caddyfile --adapter caddyfile
ExecReload=${INSTALL_DIR}/caddy reload --config ${INSTALL_DIR}/Caddyfile --adapter caddyfile
Restart=on-failure
RestartSec=3
LimitNOFILE=65536
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF
  fi

  if command -v restorecon >/dev/null 2>&1; then
    restorecon -R "$INSTALL_DIR" "$DATA_DIR" "$CADDY_STATE_DIR" "$SYSTEMD_DIR"/tlan*.service >/dev/null 2>&1 || true
  fi

  systemctl daemon-reload
  systemctl enable tlan.service
  systemctl restart tlan.service
  if (( ! NO_CADDY )); then
    systemctl enable tlan-https.service
    systemctl restart tlan-https.service
  fi
}

configure_firewall() {
  (( SKIP_FIREWALL )) && return 0

  local tcp_ports=()
  if (( NO_CADDY )); then
    if (( ALLOW_INSECURE_PUBLIC_CONTROL )); then
      tcp_ports=("$CONTROL_PORT")
    fi
  else
    tcp_ports=(80 "$HTTPS_PORT" "$ADMIN_HTTPS_PORT")
  fi

  if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
    log "Opening firewalld ports..."
    for p in "${tcp_ports[@]}"; do
      firewall-cmd --permanent --add-port="${p}/tcp" >/dev/null || warn "firewall-cmd failed for ${p}/tcp"
    done
    firewall-cmd --permanent --add-port="${STUN_PORT}/udp" >/dev/null || warn "firewall-cmd failed for ${STUN_PORT}/udp"
    firewall-cmd --reload >/dev/null || true
  elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    log "Opening UFW ports..."
    for p in "${tcp_ports[@]}"; do
      ufw allow "${p}/tcp" >/dev/null || warn "ufw failed for ${p}/tcp"
    done
    ufw allow "${STUN_PORT}/udp" >/dev/null || warn "ufw failed for ${STUN_PORT}/udp"
  else
    log "No active firewalld/ufw detected; remember to open TCP (${tcp_ports[*]}) and UDP (${STUN_PORT}) in your cloud security group."
  fi
}

verify_services() {
  sleep 1
  if ! systemctl is-active --quiet tlan.service; then
    journalctl -u tlan.service -n 40 --no-pager >&2 || true
    die "tlan.service failed to stay active."
  fi
  local ok=0
  for _ in $(seq 1 15); do
    if curl -fsS "http://127.0.0.1:${CONTROL_PORT}/health" >/dev/null 2>&1; then
      ok=1
      break
    fi
    sleep 0.5
  done
  (( ok )) || die "TLAN control health check failed on 127.0.0.1:${CONTROL_PORT}/health."

  if (( ! NO_CADDY )) && ! systemctl is-active --quiet tlan-https.service; then
    journalctl -u tlan-https.service -n 40 --no-pager >&2 || true
    die "tlan-https.service (Caddy) failed to stay active."
  fi
}

do_uninstall() {
  log "Stopping and disabling TLAN systemd services..."
  for unit in tlan-https.service tlan.service; do
    systemctl stop "$unit" >/dev/null 2>&1 || true
    systemctl disable "$unit" >/dev/null 2>&1 || true
    rm -f "${SYSTEMD_DIR}/${unit}"
  done
  systemctl daemon-reload
  rm -rf "$INSTALL_DIR"
  log "Removed ${INSTALL_DIR} and systemd service files."
  log "Kept configuration & state in ${DATA_DIR} (remove manually if no longer needed: rm -rf ${DATA_DIR} ${CADDY_STATE_DIR})."
}

print_summary() {
  local host_display="${PUBLIC_HOST:-<YOUR_SERVER_IP>}"
  printf '\n============================================================\n'
  printf '  TLAN Server Installed Successfully!\n'
  printf '============================================================\n'
  if (( NO_CADDY )); then
    printf '  Client Server Address : http://%s:%s\n' "$host_display" "$CONTROL_PORT"
    printf '  Admin Web Console     : http://127.0.0.1:%s/admin\n' "$ADMIN_PORT"
  else
    printf '  Client Server Address : https://%s:%s\n' "$host_display" "$HTTPS_PORT"
    printf '  Admin Web Console     : https://%s:%s/admin\n' "$host_display" "$ADMIN_HTTPS_PORT"
  fi
  printf '  STUN Address          : %s:%s\n' "$host_display" "$STUN_PORT"
  printf '  Config File (0600)    : %s\n' "$CONFIG_FILE"
  if [[ -n "$JOIN_CODE" ]]; then
    printf '  Member Join Code      : %s\n' "$JOIN_CODE"
  fi
  if [[ -n "$ADMIN_TOKEN" ]]; then
    printf '  Admin Token           : (the token you configured; also in %s)\n' "$CONFIG_FILE"
  fi
  if (( ! NO_CADDY )) && [[ "$PUBLIC_HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || -z "$PUBLIC_HOST" ]]; then
    printf '  Internal Root CA      : %s/.local/share/caddy/pki/authorities/local/root.crt\n' "$CADDY_STATE_DIR"
    printf '  (Install that root.crt into Windows Trusted Root CAs when using a raw IP over HTTPS.)\n'
  fi
  printf '\n  Service Management:\n'
  printf '    systemctl status tlan\n'
  if (( ! NO_CADDY )); then
    printf '    systemctl status tlan-https\n'
  fi
  printf '    journalctl -u tlan -f\n'
  printf '============================================================\n'
}

main() {
  parse_args "$@"
  validate_port "control port" "$CONTROL_PORT"
  validate_port "HTTPS port" "$HTTPS_PORT"
  validate_port "admin port" "$ADMIN_PORT"
  validate_port "admin HTTPS port" "$ADMIN_HTTPS_PORT"
  validate_port "STUN port" "$STUN_PORT"

  detect_os_and_arch
  log "Detected ${OS_PRETTY} (${ARCH}, package manager: ${PKG_MGR})."

  if (( CHECK_ONLY )); then
    log "Prerequisite check passed."
    exit 0
  fi

  require_root "$@"

  if (( UNINSTALL )); then
    do_uninstall
    exit 0
  fi

  ensure_base_tools
  collect_user_config
  build_or_install_binary
  ensure_accounts_and_dirs
  ensure_caddy
  write_server_config
  write_caddyfile_and_units
  configure_firewall
  verify_services
  print_summary
}

main "$@"
