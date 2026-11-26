//go:build windows

package main

import (
	"errors"
	"testing"

	frpctl "github.com/private-radminlan/lanmesh/internal/frp"
	"github.com/private-radminlan/lanmesh/internal/frpauth"
)

func TestBindFRPServerToHostTracksLoginServer(t *testing.T) {
	cfg := frpctl.NewDefaultConfig()
	cfg.Profile.Server.Host = "old.example.com"
	cfg.Profile.Server.TLSServerName = "old.example.com"
	cfg.Profile.Server.Port = 0
	cfg.Profile.Server.Transport = ""

	bound := bindFRPServerToHost(cfg, "203.0.113.10")
	if bound.Profile.Server.Host != "203.0.113.10" {
		t.Fatalf("Host = %q, want 203.0.113.10", bound.Profile.Server.Host)
	}
	if bound.Profile.Server.TLSServerName != "203.0.113.10" {
		t.Fatalf("TLSServerName = %q, want 203.0.113.10", bound.Profile.Server.TLSServerName)
	}
	if bound.Profile.Server.Port != 7000 {
		t.Fatalf("Port = %d, want 7000", bound.Profile.Server.Port)
	}
	if bound.Profile.Server.Transport != "tcp" {
		t.Fatalf("Transport = %q, want tcp", bound.Profile.Server.Transport)
	}

	custom := frpctl.NewDefaultConfig()
	custom.Profile.Server.Host = "10.0.0.1"
	custom.Profile.Server.TLSServerName = "frp.custom.example"
	custom.Profile.Server.Port = 7443
	boundCustom := bindFRPServerToHost(custom, "203.0.113.10")
	if boundCustom.Profile.Server.TLSServerName != "frp.custom.example" {
		t.Fatalf("distinct custom TLSServerName overwritten: %q", boundCustom.Profile.Server.TLSServerName)
	}
	if boundCustom.Profile.Server.Port != 7443 {
		t.Fatalf("existing Port = %d, want 7443", boundCustom.Profile.Server.Port)
	}
}

func TestResolveFRPServerMode(t *testing.T) {
	kind, sid := resolveFRPServerMode(frpauth.Capabilities{Mode: frpauth.ModeManaged, ServerID: "frps-managed-1"}, nil)
	if kind != "managed" || sid != "frps-managed-1" {
		t.Fatalf("managed capabilities = (%q, %q)", kind, sid)
	}

	kind, sid = resolveFRPServerMode(frpauth.Capabilities{Mode: frpauth.ModeDisabled}, nil)
	if kind != "private_token" || sid != "" {
		t.Fatalf("disabled capabilities = (%q, %q)", kind, sid)
	}

	kind, sid = resolveFRPServerMode(frpauth.Capabilities{Mode: frpauth.ModeManaged, ServerID: "ignored"}, errors.New("unreachable"))
	if kind != "private_token" || sid != "" {
		t.Fatalf("error fallback = (%q, %q)", kind, sid)
	}
}
