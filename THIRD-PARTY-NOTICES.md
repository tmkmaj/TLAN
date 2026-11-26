# Third-party components

TLAN uses independently developed, unmodified third-party components.
The project is not affiliated with Radmin, WireGuard LLC, or Wintun.

- wireguard-go, MIT: golang.zx2c4.com/wireguard, pinned in go.mod.
  Copyright WireGuard LLC. Full license: vendor/golang.zx2c4.com/wireguard/LICENSE.
- Wintun Go bindings, MIT: golang.zx2c4.com/wintun. Full license in vendor/.
- Signed Wintun 0.14.1 AMD64 binary: https://www.wintun.net/builds/wintun-0.14.1.zip.
  Archive SHA-256: 07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51.
  DLL SHA-256: e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce.
  Distributed unmodified and only used through its documented API.
  Full binary license: assets/windows/WINTUN-LICENSE.txt, included in client ZIP.
- Walk and win, BSD-style: github.com/lxn/walk and github.com/lxn/win.
  Full license texts are included in vendor/.
- Go x/sys, x/crypto and x/net, BSD-style, and Knetic/govaluate, MIT.
  Full licenses are included in their respective vendor/ directories.
- go-yaml v3, MIT and Apache-2.0: gopkg.in/yaml.v3, pinned in go.mod.
  Full license and notice are included under vendor/gopkg.in/yaml.v3/.
- fatedier/frp v0.71.1, Apache-2.0: https://github.com/fatedier/frp.
  The client bundles a binary built from the pinned upstream source (build tags `frpc,noweb`) at
  runtime/frp/0.71.1/windows-amd64/frpc.exe with SHA-256
  509f4fa082bf9b85f9ad27b45d37a89a8accb011f3b724cff352dfac90a94feb.
  The independent server package bundles a Linux `frps` binary built from the same source (build tags `frps,noweb`) with SHA-256
  2fb8da8392cf2b332bfcc540f075e928a82d1a106df0b8fcfcf13497149f8c48.
  Source tag object: 72d643d661dcb686087e342142a70f8f4698e29f;
  commit: d8cf1800dc1abd7fda1828cab105d7a6b5a50eb1.
  Full license: assets/frp/licenses/FRP-LICENSE.txt, included in both packages.

Build scripts include these license texts in release packages.

The single-file Linux server installer additionally bundles the unmodified
Caddy 2.11.7 official linux_amd64 binary (Apache-2.0), from
https://github.com/caddyserver/caddy/releases/tag/v2.11.7.
Its Apache license is included as licenses/caddy-Apache-2.0.txt.


