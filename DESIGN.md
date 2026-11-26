# Design System — TLAN Windows Client

This document records the visual system, token definitions, typography, navigation skeleton, and native Win32/GDI+ rendering rules for `cmd/client`.

## 1. Design Direction & Mode

- **Surface Mode**: `Operate` (`adaptive` native Windows 10/11 desktop GUI via `github.com/lxn/walk` and Windows `gdiplus.dll` / `uxtheme.dll` / `dwmapi.dll`).
- **Architecture**: Full-width **Top Command Deck** (`topDeck`, 58px) pairing with **2-Column Split Cockpits** for Login (`pageJoin`, supporting bare `IP:端口` and regular/admin key detection) and Virtual LAN (`pagePower`), plus a streamlined **Quick Port-Mapping Cockpit** (`pageFRP` with inline local IP/port/server port composer + native Windows listening-process picker) and Admin Member Matrix (`pageAdmin`).
- **Visual Identity**: **Deep Space Cobalt & Electric Sapphire** (`darkPalette`) and **Arctic Alloy & Electric Cobalt** (`lightPalette`), paired with GDI+ HUD tactical corner framing, gradient reactor buttons, and 60fps interactive radar/blueprint motion.

## 2. Color Tokens (`cmd/client/theme_windows.go`)

Every slot within each palette holds a distinct RGB value so `paletteReplacements` performs deterministic 1:1 switching across `system`, `light`, and `dark` appearances (verified by `TestPaletteSlotsAreUnique`).

### Light Palette (`lightPalette`)

| Token | RGB | Hex | Role |
|---|---|---|---|
| `background` | `236, 242, 252` | `#ECF2FC` | Window & workspace canvas |
| `sidebar` | `245, 249, 255` | `#F5F9FF` | Top Command Deck & split onboarding left pane |
| `surface` (`uiWhite`) | `255, 255, 255` | `#FFFFFF` | Primary cards, inputs, table surfaces |
| `tableAlt` | `241, 246, 254` | `#F1F6FE` | HUD radar plate, local telemetry box, alternating table rows & header |
| `ink` | `11, 21, 40` | `#0B1528` | Primary text, secondary button labels |
| `muted` | `82, 103, 138` | `#52678A` | Captions, metadata, offline rows |
| `border` | `205, 220, 244` | `#CDDCF4` | 1px structural dividers & card borders |
| `borderStrong` | `168, 192, 232` | `#A8C0E8` | Secondary control outlines, topology standby strokes |
| `blue` | `37, 99, 235` | `#2563EB` | Electric Cobalt primary accent, active topology links, virtual IP readouts |
| `blueDeep` | `29, 78, 216` | `#1D4ED8` | Primary gradient anchor & pressed CTA |
| `blueHover` | `59, 130, 246` | `#3B82F6` | Hovered gradient highlight, active hub core |
| `blueSelected` | `30, 64, 175` | `#1E40AF` | Light-mode active command tab ink |
| `blueSoft` | `235, 244, 255` | `#EBF4FF` | Tab hover background, notice banner |
| `blueHalo` | `219, 234, 254` | `#DBEAFE` | Active command tab pill, live HUD halo |
| `blueBorder` | `56, 189, 248` | `#38BDF8` | Sky-cyan focus rim, HUD corner brackets & radar sweep beam |
| `onAccent` | `254, 255, 255` | `#FEFFFF` | High-contrast white ink on cobalt fills |
| `focus` | `14, 165, 233` | `#0EA5E9` | Packet pulse core & keyboard focus outline |
| `success` | `5, 150, 105` | `#059669` | Live online status & verified peer nodes |
| `warning` | `217, 119, 6` | `#D97706` | Handshaking / connecting / retry states |
| `danger` | `220, 38, 38` | `#DC2626` | Errors, blocked devices |

### Dark Palette (`darkPalette`)

| Token | RGB | Hex | Role |
|---|---|---|---|
| `background` | `6, 11, 22` | `#060B16` | Deep-space cockpit canvas |
| `sidebar` | `10, 17, 34` | `#0A1122` | Top Command Deck & split onboarding left pane |
| `surface` (`uiWhite`) | `14, 24, 46` | `#0E182E` | Primary cards, inputs, table surfaces |
| `tableAlt` | `19, 32, 60` | `#13203C` | HUD radar plate, local telemetry box, alternating table rows & header |
| `ink` | `240, 246, 255` | `#F0F6FF` | Primary text, secondary button labels |
| `muted` | `138, 162, 198` | `#8AA2C6` | Captions, metadata, offline rows |
| `border` | `29, 51, 92` | `#1D335C` | 1px structural dividers & card borders |
| `borderStrong` | `45, 78, 138` | `#2D4E8A` | Secondary control outlines, topology standby strokes |
| `blue` | `59, 130, 246` | `#3B82F6` | Electric Sapphire accent, virtual IP readouts & live vectors |
| `blueDeep` | `29, 78, 216` | `#1D4ED8` | Primary gradient anchor |
| `blueHover` | `96, 165, 250` | `#60A5FA` | Hovered CTA specular boost, active topology hub |
| `blueSelected` | `37, 99, 235` | `#2563EB` | Gradient top anchor & pressed pill transition |
| `blueSoft` | `16, 34, 68` | `#102244` | Tab hover background, notice banner |
| `blueHalo` | `22, 49, 96` | `#163160` | Active command tab pill, live HUD halo |
| `blueBorder` | `56, 189, 248` | `#38BDF8` | Neon ice-cyan HUD brackets, active tab beam, radar sweep |
| `onAccent` | `255, 255, 255` | `#FFFFFF` | High-contrast white text/icons on sapphire fills |
| `focus` | `125, 211, 252` | `#7DD3FC` | Dark-mode active command tab ink, packet pulse core & focus ring |
| `success` | `52, 211, 153` | `#34D399` | Live online status & verified peer nodes |
| `warning` | `251, 191, 36` | `#FBBF24` | Handshaking / connecting / retry states |
| `danger` | `248, 113, 113` | `#F87171` | Errors, blocked devices |

## 3. Typography (`uiFont` & `uiMonoFont`)

- **Onboarding Headline**: `Microsoft YaHei UI` 16pt Bold
- **Section & Panel Headers**: `Microsoft YaHei UI` 12pt Bold (16pt Bold for Admin KPI numerals)
- **Command Deck Tabs, Buttons & Table Cells**: `Microsoft YaHei UI` 9pt (Bold on primary CTAs, active tabs, and table headers)
- **Virtual IP Readout**: `Consolas` 15pt Bold
- **Node Endpoint / Traffic / Blueprint Subtitle / Logs**: `Consolas` 8pt–10pt Regular/Bold

## 4. Custom GDI+ Surfaces & Animations (`cmd/client/drawing_windows.go`, `cmd/client/controls_windows.go`)

- **`brandEmblem`**: Sapphire-to-cobalt gradient badge (`roundedGradient`) with an orbital ring halo framing a crisp white 3-node T-topology emblem.
- **`powerAnimated` (Widescreen HUD Mode `264×124`)**: Double-buffered tactical telemetry & reactor dial — left 60% renders concentric range rings, cardinal ticks, a rotating conical radar sweep beam (`pieAlpha`), and animated traveling packet pulses; right 40% renders an orbiting segmented bezel reactor dial with smooth hover/power glow transitions (`ensureAnimLoop`).
- **`joinBlueprintAnimated` (`242×174`)**: Live double-buffered topology blueprint inside the onboarding deck with expanding hub ripple and animated packet pulses along encrypted links.
- **`hudCorners`**: Subtle top specular rim and precision L-shaped corner brackets (`roundView{hud: true}`) framing tactical surfaces.
- **`paintedButton`, `paintedNavButton` & `deckScanBarView`**: Unified size & semantic tiers (`heroButton` 40px r=9, `actionButton` 34px r=8, `compactButton` 30px r=7 across `btnPrimary`/`btnSecondary`/`btnDanger`/`btnGhost`, and `34px` top utility tabs including unified `连接诊断`/`关于`/`菜单`). Zero-flicker double-buffered rendering (`drawBufferedDC`), explicit Win32 `WM_MOUSEMOVE` + `TrackMouseEvent(TME_LEAVE)` hover state with pointing-hand cursor (`IDC_HAND`), sapphire outer hover blooms + sliding top-edge specular sheen on primary CTAs, tactile crimson hover on destructive actions, center-outward neon active tab laser bar, and a double-buffered 2px electric-cyan deck scan sweep (`triggerDeckScan`) on page/power transitions (`--ui-smoke-test` disables timers cleanly via `smokeMode`).
- **Port Forwarding Server Lock (`cmd/client/frp_ui_windows.go`)**: `pageFRP` binds `Server.Host` strictly to the logged-in server (`bindFRPServerToHost`), exposes only read-only host display + `认证凭据` dialog (CA certificate, token, port, automatic `GET /api/v1/frp/capabilities` mode resolution) without editable server IP inputs, and omits `私有访问`, `目标成员授权`, multi-profile/import-export, and legacy HTTP/STCP/XTCP sub-forms.
- **Resize & Repaint Integrity (`vendor/github.com/lxn/walk/layout.go`, `form.go`, `window.go`, `mainwindow.go`, `container.go`, `cmd/client/ui_windows.go`)**: Virtual `wb.window.SetBoundsPixels` dispatch ensures `FormBase.proposedSize` is initialized on startup and updated with post-clamp bounds, `FormBase.startLayout` and `MainWindow.WndProc` keep `clientComposite` locked to `ClientBoundsPixels()`, `WindowBase.WndProc` erases exposed form background via `form.Background()`, per-layout buffered `done` channels eliminate resize race conditions, and `SWP_NOCOPYBITS` prevents stale bit-copy ghosting.
