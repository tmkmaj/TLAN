# Egress gateway deployment (explicit proxy)

This directory contains the deployment assets for the server side of the
"应用流量转发" (application egress) module. The gateway and Windows helper are
implemented for **explicit SOCKS5 proxy** mode. Transparent per-process capture
still requires a signed WFP component and is not included.

These assets are not yet merged into `build-server-installer.ps1` or
`deploy/install-server.sh`; deploy them deliberately on a Linux host.

## Files

- `egress-gateway.yaml.example` — strict YAML configuration sample. Copy it to
  `/etc/tlan-egress/egress-gateway.yaml` and edit the interface, TLS paths and
  policy. Unknown YAML fields are rejected.
- `tlan-egress-gateway.service` — systemd unit. It needs `CAP_NET_ADMIN` for
  NAT and `ip_forward`, and it only manages rules carrying the product marker.

## Requirements

1. A real Linux host with `nftables` (preferred) or `iptables`, and
   `net.ipv4.ip_forward` controllable from systemd.
2. A TLS certificate for the gateway domain. Clients pin the issuing CA.
3. The egress interface must exist before start-up; the service refuses to
   apply NAT otherwise.
4. A lease source: either a private `lease_secret_file` or the gateway's
   standalone lease API.

## Before starting

```sh
sudo /opt/tlan-egress/egress-gateway -config /etc/tlan-egress/egress-gateway.yaml -check
sudo /opt/tlan-egress/egress-gateway -config /etc/tlan-egress/egress-gateway.yaml -print-plan
```

`-check` validates the YAML and probes NAT capabilities without applying rules.
`-print-plan` prints the exact NAT plan. The example test suite loads the
checked-in YAML sample with strict unknown-field rejection.

## Safety boundaries

- The gateway rejects loopback, private, link-local, multicast, unspecified and
  cloud-metadata targets, plus a configurable deny-port list. It must never be
  usable as an open proxy.
- NAT rules carry a unique comment/marker. Rollback removes only marked rules and
  restores the previous `ip_forward` value.
- The gateway CLI accepts `ipv6_policy: "block"` only; `allow_public` and `proxy`
  are rejected so IPv6 cannot silently bypass the explicit-proxy boundary.
- `dns_policy` accepts `remote` or `block`; `local` is rejected. In this release,
  `dns_servers` is a DNS-destination allowlist. Target hostname resolution still
  uses the gateway host resolver and is not a custom DNS client.
- `max_rate_bps` is recorded in the lease but is not enforced yet. Connection and
  byte quotas are enforced.
- The Windows client exposes a loopback SOCKS5 helper only. It does not capture
  traffic transparently and does not claim per-process isolation in explicit mode.

## Not yet implemented

- Signed Windows WFP component for transparent per-process redirection.
- Real Linux-host NAT/systemd acceptance and cross-public-network dual-host
  acceptance (see `docs/EGRESS-VALIDATION.md`).
- Integration of the standalone gateway into the existing control-plane
  installer and lease API.