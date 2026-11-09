# Egress gateway deployment (skeleton)

This directory holds the server-side skeleton for the "应用流量转发" (application
egress) module. It is **not** wired into `build-server-installer.ps1` or
`deploy/install-server.sh` yet: the gateway binary, the lease API and the
Windows capture layer are still under development.

## Files

- `egress-gateway.toml.example` — configuration sample. Copy to
  `/etc/tlan-egress/egress-gateway.toml` and edit the interface, TLS paths and
  policy.
- `tlan-egress-gateway.service` — systemd unit. It needs `CAP_NET_ADMIN` for
  NAT and `ip_forward`, and it only manages rules carrying the product marker.

## Requirements

1. A real Linux host with `nftables` (preferred) or `iptables`, and
   `net.ipv4.ip_forward` controllable from systemd.
2. A TLS certificate for the gateway domain. Clients pin the issuing CA.
3. The egress interface must exist before start-up; the service refuses to
   apply NAT otherwise.
4. A lease source: either the TLAN control plane (future `/api/v1/egress/leases`
   endpoints) or the private `lease_secret_file` mode.

## Safety boundaries

- The gateway rejects loopback, private, link-local, multicast, unspecified and
  cloud-metadata targets, plus a configurable deny-port list. It must never be
  usable as an open proxy.
- NAT rules carry a unique comment/marker. Rollback removes only marked rules and
  restores the previous `ip_forward` value.
- `ipv6_policy = "block"` is the only supported value in the first release;
  clients must block matching IPv6 traffic rather than silently direct-connect.

## Not yet implemented

- Gateway binary and systemd installation script.
- Real end-to-end validation with a Windows client.
- Signed Windows WFP component for per-process transparent redirection. Without
  it the client cannot claim transparent forwarding.
