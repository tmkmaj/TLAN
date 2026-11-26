//go:build windows

package main

import (
	"net"
	"os"
	"strings"
	"testing"

	frpctl "github.com/private-radminlan/lanmesh/internal/frp"
)

func TestNormalizeLocalTargetIP(t *testing.T) {
	tests := []struct {
		in   string
		kind string
		host string
		ok   bool
	}{
		{"", "loopback", "127.0.0.1", true},
		{"0.0.0.0", "loopback", "127.0.0.1", true},
		{"127.0.0.1", "loopback", "127.0.0.1", true},
		{"localhost", "loopback", "127.0.0.1", true},
		{"192.168.1.50", "lan", "192.168.1.50", true},
		{"10.0.0.12", "lan", "10.0.0.12", true},
		{"8.8.8.8", "", "", false},
		{"invalid-ip", "", "", false},
	}
	for _, tc := range tests {
		kind, host, err := normalizeLocalTargetIP(tc.in)
		if tc.ok && (err != nil || kind != tc.kind || host != tc.host) {
			t.Fatalf("normalizeLocalTargetIP(%q) = (%q, %q, %v); want (%q, %q, nil)", tc.in, kind, host, err, tc.kind, tc.host)
		}
		if !tc.ok && err == nil {
			t.Fatalf("normalizeLocalTargetIP(%q) unexpectedly succeeded: (%q, %q)", tc.in, kind, host)
		}
	}
}

func TestFilterLocalPortEntriesAndSuggest(t *testing.T) {
	entries := []localPortEntry{
		{PID: 100, ProcessName: "javaw.exe", Protocol: "tcp", BindIP: "0.0.0.0", TargetIP: "127.0.0.1", Port: 25565},
		{PID: 200, ProcessName: "nginx.exe", Protocol: "tcp", BindIP: "127.0.0.1", TargetIP: "127.0.0.1", Port: 8080},
		{PID: 300, ProcessName: "TerrariaServer.exe", Protocol: "udp", BindIP: "0.0.0.0", TargetIP: "127.0.0.1", Port: 7777},
	}
	got := filterLocalPortEntries(entries, "25565", "")
	if len(got) != 1 || got[0].ProcessName != "javaw.exe" {
		t.Fatalf("filter by port = %#v", got)
	}
	got = filterLocalPortEntries(entries, "", "udp")
	if len(got) != 1 || got[0].Port != 7777 {
		t.Fatalf("filter by proto = %#v", got)
	}

	existing := []frpctl.Rule{
		{Name: "javaw_25565", Type: "tcp", Exposure: frpctl.Exposure{RemotePort: 60000}},
	}
	name := suggestRuleName("javaw.exe", 25565, existing)
	if name != "javaw_25565_2" {
		t.Fatalf("suggestRuleName = %q, want javaw_25565_2", name)
	}
	if port := suggestRemotePort(existing, 25565); port != 60001 {
		t.Fatalf("suggestRemotePort = %d, want 60001", port)
	}
	if port := suggestRemotePortInRange(existing, 55005, 55000, 55100); port != 55005 {
		t.Fatalf("suggestRemotePortInRange = %d, want 55005", port)
	}
}

func TestBuildQuickFRPRules(t *testing.T) {
	existing := []frpctl.Rule{
		{ID: "r1", Name: "Web", Type: "tcp", Exposure: frpctl.Exposure{RemotePort: 30000}},
	}
	rules, err := buildQuickFRPRules(existing, "MC服务器", "127.0.0.1", 25565, 30001, "tcp+udp")
	if err != nil {
		t.Fatalf("buildQuickFRPRules error: %v", err)
	}
	if len(rules) != 2 || rules[0].Type != "tcp" || rules[1].Type != "udp" || !strings.HasSuffix(rules[0].Name, "_TCP") {
		t.Fatalf("unexpected quick rules: %#v", rules)
	}
	if _, err := buildQuickFRPRules(existing, "Dup", "127.0.0.1", 8080, 30000, "tcp"); err == nil {
		t.Fatal("expected duplicate remote port conflict")
	}
}

func TestListLocalListeningPortsFindsOwnListener(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen loopback: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().(*net.TCPAddr)
	myPID := uint32(os.Getpid())

	entries, err := listLocalListeningPorts()
	if err != nil {
		t.Fatalf("listLocalListeningPorts: %v", err)
	}
	found := false
	for _, entry := range entries {
		if entry.Protocol == "tcp" && entry.Port == addr.Port && entry.PID == myPID {
			found = true
			if entry.TargetIP != "127.0.0.1" {
				t.Fatalf("listener TargetIP = %q, want 127.0.0.1", entry.TargetIP)
			}
			break
		}
	}
	if !found {
		t.Fatalf("own test listener 127.0.0.1:%d (pid=%d) not returned by listLocalListeningPorts", addr.Port, myPID)
	}
}
