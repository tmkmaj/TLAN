# Product

<!-- impeccable:product-schema 1 -->

## Platform

adaptive

## Users

Self-hosted private network operators and their invited friends or teammates running Windows 10/11 amd64 desktop clients to connect over encrypted virtual LANs and controlled FRP port forwarding against a private Linux server.

## Product Purpose

TLAN lets an operator deploy a private control, STUN, relay, and optional managed FRPS stack on their own server, and gives Windows users a single-window native client to join a private virtual LAN, inspect peer connectivity and latency, manage FRP port-forwarding rules, and (with an admin token) administer network members.

## Positioning

A self-hosted alternative to Radmin LAN that combines WireGuard + Wintun peer-to-peer virtual LAN meshing (with automatic relay fallback) and policy-controlled FRP publishing in a lightweight Windows native GUI without third-party cloud accounts or browser runtimes.

## Operating Context

- Desktop client runs as an elevated Windows 10/11 amd64 GUI (`github.com/lxn/walk` + `win` + GDI+) because Wintun virtual adapter creation and route configuration require administrator privileges.
- Users launch the client, enter the server `IP:端口` and an access key (regular user key or admin key), toggle the virtual LAN connection on/off, check peer virtual IPs and direct/relay latency, copy IPs for LAN gaming or remote access, map local processes or custom `IP:端口` pairs directly to server ports, and (when enrolled with an admin key) manage connected members in the `节点管理` panel.
- Client credentials, DPAPI secrets, and settings are isolated per Windows user; diagnostic exports redact secrets automatically.

## Capabilities and Constraints

- **UI Toolkit**: Go `github.com/lxn/walk` (Win32 controls) and Windows `gdiplus.dll` / `uxtheme.dll` / `dwmapi.dll` custom painting; no webview, Electron, or external rendering runtime.
- **Core Pages**: Join/Enrollment (`pageJoin`), Virtual LAN Mesh Console (`pagePower`), Streamlined Port Forwarding (`pageFRP` locked to the logged-in server host), and Admin Member Management (`pageAdmin`, unlocked only when enrolled with admin token), plus Settings, Version Info, Diagnostics, Port Mapping Credentials/Edit dialogs, Local Process Picker dialog, and Tray menu.
- **Confirmed UX Direction**:
  - Compact Radmin LAN / Tailscale-style virtual LAN console: compact top connection control bar + local node IP bar with one-click copy + expansive peer table with double-click / context-menu IP copy.
  - Direct Port Forwarding without bloated sub-features: no editable server IP UI inside port forwarding (bound strictly to the logged-in server), no unused `私有访问` (visitors), `目标成员授权`, multi-profile management, or advanced HTTP/STCP/XTCP sub-forms; quick inline composer (`本地 IP` + `本地端口` → `服务器端口` + `协议`) paired with native Windows listening-process selection.
  - Unified button sizing tiers (`heroButton`, `actionButton`, `compactButton`, top utility tabs) with explicit Win32 mouse hover tracking (`WM_MOUSEMOVE` + `TrackMouseEvent`), pointing hand cursor (`IDC_HAND`), semantic hover/press glow animations, and zero-flicker double-buffered rendering.
  - Modern geometric vector brand emblem rendered via GDI+ and synchronized to `assets/branding/TLAN-icon.png`.
- **Technical Constraints**: Existing smoke checks (`--ui-smoke-test`) and preview fixtures (`--ui-preview`) must remain functional and pass; existing backend/FRP/mesh security boundaries remain untouched.

## Brand Commitments

- Product name: `TLAN` (`TLAN - TLAN` window title).
- Modern geometric T-node emblem in crisp vector / high-DPI PNG (`assets/branding/TLAN-icon.png`), supporting both light and dark Windows appearances (`system`, `light`, `dark`).

## Evidence on Hand

- Incumbent Windows UI source under `cmd/client/` (`ui_windows.go`, `desktop_windows.go`, `theme_windows.go`, `controls_windows.go`, `drawing_windows.go`, `frp_ui_windows.go`, `local_ports_windows.go`, `admin_panel_windows.go`, `client_settings_windows.go`, `ui_check_windows.go`).
- Smoke test runner (`--ui-smoke-test`) and preview screenshots under `docs/screenshots/`.

## Product Principles

1. **Operate-first clarity**: Primary connection state, local virtual IP, and peer reachability are readable in one glance without decorative clutter.
2. **Concise native copy**: Every label, status, and error speaks like a crisp desktop utility—no filler disclaimers, internal schema lectures, or AI-generated boilerplate.
3. **One control per purpose**: No duplicate power buttons, duplicate diagnostic/refresh buttons, or dead-end actions on screens where prerequisites are missing.
4. **Native Windows precision**: Consistent `Microsoft YaHei UI` and `Consolas` typography, frameless tables, high-contrast focus states, and cohesive light/dark surfaces.
