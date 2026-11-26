# TLAN

**[中文文档](README.md)**

**TLAN** is a self-hosted private virtual LAN (mesh VPN) designed for multiplayer gaming, remote collaboration, and private service sharing.  
It consists of a **Linux server** (control plane, TLS relay, STUN, web admin console, and managed FRP support) and a **Windows desktop client** (Wintun virtual adapter, automatic P2P / relay failover, and built-in FRP port mapping).

## Key Features

- **Private Virtual Mesh LAN**: Encrypted peer-to-peer tunnels powered by WireGuard + Wintun with automatic virtual IP assignment.
- **P2P First + Automatic Relay Fallback**: Integrated UDP STUN hole-punching and latency probing; automatically switches to TLS TCP relay whenever direct P2P cannot traverse restrictive NATs.
- **Customizable Username**: Set your own display name on first join, or rename yourself at any time from the client UI with instant synchronization to peers.
- **Bilingual Windows Client (EN / 中文)**: Live language toggle (`Follow system` / `简体中文` / `English`), Light/Dark/System themes, system tray support, and one-click diagnostic bundle export.
- **Built-in Port Mapping (FRP)**: Pick a local listening process directly in the UI and expose TCP/UDP ports through an FRPS node with admin-managed port range controls.
- **One-Click Linux Deployment**: `install.sh` checks your environment, installs missing dependencies automatically, prompts for your **Admin Token** and network settings, configures `tlan-config.yml` (`0600`), sets up `systemd` services and firewall rules, and includes a web admin console (`/admin`) and Prometheus metrics (`/metrics`).

---

## Quick Start: One-Click Linux Server Install

Supported distributions: **Debian, Ubuntu, CentOS, RHEL, Rocky Linux, AlmaLinux, Fedora** (requires `root`, `systemd`, and `x86_64` / `arm64`).

### Option 1: Interactive Installation

```bash
git clone <your-repo-url> TLAN
cd TLAN
sudo bash install.sh
```

What `install.sh` does:
1. Validates OS, CPU architecture, package manager (`apt` / `dnf` / `yum`), and active `systemd` (reports clear, actionable errors on unsupported systems or non-systemd containers).
2. Automatically installs missing prerequisites (`curl`, `tar`, `gzip`, `openssl`, `ca-certificates`, `libcap`) and Go (>= `1.23.1`) if missing or outdated.
3. Prompts you for configuration fields:
   - **Admin Token** (your required administrator secret for the web console & client admin mode; press Enter to auto-generate one).
   - **Join Code** (shared key for network members; press Enter to auto-generate).
   - **Public IP or Domain**, **Virtual Network Name** (default `TLAN`), and **CIDR** (default `10.240.0.0/24`).
4. Builds `/opt/tlan/tlan-server`, installs Caddy for HTTPS termination, and writes `/var/lib/tlan/tlan-config.yml` (`0600`).
5. Creates unprivileged service accounts (`tlan`, `tlanhttps`), configures & enables `tlan.service` and `tlan-https.service` via `systemctl`, opens `ufw` / `firewalld` ports, and runs a health check.

### Option 2: Non-Interactive Installation

```bash
sudo bash install.sh \
  --admin-token "YOUR_STRONG_ADMIN_TOKEN" \
  --join-code "YOUR_MEMBER_JOIN_CODE" \
  --host "your.server.ip.or.domain" \
  --network-name "TLAN" \
  --cidr "10.240.0.0/24" \
  --non-interactive
```

Run `bash install.sh --help` for all flags (`--no-caddy`, `--binary`, `--https-port`, `--stun-port`, `--skip-firewall`, `--reconfigure`, `--check`, `--uninstall`).

### Required Firewall / Cloud Security Group Ports

| Port / Protocol | Purpose | Notes |
| --- | --- | --- |
| `TCP 8443` | Control API & TLS relay gateway (Caddy) | Default client connection port |
| `TCP 8444` | Web Admin Console (Caddy) | Access `https://<your-host>:8444/admin` |
| `TCP 80` | ACME HTTP challenge for domain TLS | Required when using automatic Let's Encrypt |
| `UDP 3478` | STUN UDP probing & NAT traversal | Used for latency charts and P2P punching |

> **Note**: When deploying with a raw public IP (no domain), Caddy generates certificates using its internal CA. Export `/var/lib/tlan-caddy/.local/share/caddy/pki/authorities/local/root.crt` to your Windows clients' Trusted Root Certification Authorities store.

### Service Management

```bash
sudo systemctl status tlan tlan-https
sudo journalctl -u tlan -f
sudo systemctl restart tlan
```

---

## Building the Windows Client

### Prerequisites

- Windows 10/11 (`amd64`)
- Go >= 1.23.1
- `go-winres` (`go install github.com/tc-hib/go-winres@latest`)

### Build Commands

```powershell
# Build generic open-source client (users enter server address in UI)
.\build-windows-client.ps1

# Or bake a default server / STUN endpoint into the client binary
.\build-windows-client.ps1 -ServerURL "https://your-server.example.com:8443" -STUNAddress "your-server.example.com:3478"
```

Outputs are created at `dist\windows\TLAN.exe` (alongside `wintun.dll`, `frpc.exe`, `tlan-icon.png`) and `dist\TLAN-client-windows-amd64.zip`.

---

## Security & Third-Party Notices

- Zero hardcoded public IPs, domains, or default credentials exist in source code or build scripts.
- Never commit `tlan-config.yml` or runtime state directories containing your live `admin_token` or `join_code`.
- See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) for third-party component licenses.
