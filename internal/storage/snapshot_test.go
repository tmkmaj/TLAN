package storage

import (
	"encoding/base64"
	"path/filepath"
	"testing"

	"github.com/private-radminlan/lanmesh/core"
)

func TestStoreSnapshotsDoNotAliasState(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	n, err := s.EnsurePrivateNetwork("friends", "friends-code", "10.243.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	_, member, _, err := s.EnrollPrivate(core.RegisterDeviceRequest{DeviceID: "device-a", WireGuardPublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32))}, "friends-code")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("enrollment forwarding", func(t *testing.T) {
		*member.Forwarding = true
		devices, _ := s.ListDevices(n.ID)
		if *devices[0].Forwarding {
			t.Error("enrollment result changed stored forwarding")
		}
	})
	t.Run("forwarding result", func(t *testing.T) {
		device, err := s.SetForwarding(n.ID, member.ID, true)
		if err != nil {
			t.Fatal(err)
		}
		*device.Forwarding = false
		devices, _ := s.ListDevices(n.ID)
		if !*devices[0].Forwarding {
			t.Error("forwarding result changed stored forwarding")
		}
	})
	t.Run("device listing", func(t *testing.T) {
		_, _ = s.SetForwarding(n.ID, member.ID, true)
		devices, _ := s.ListDevices(n.ID)
		*devices[0].Forwarding = false
		again, _ := s.ListDevices(n.ID)
		if !*again[0].Forwarding {
			t.Error("device listing changed stored forwarding")
		}
	})
	t.Run("candidates", func(t *testing.T) {
		input := []core.Candidate{{Kind: core.CandidateHost, Transport: core.TransportUDP, Address: "127.0.0.1:1234"}}
		saved, err := s.SetCandidates(core.NetworkID(n.ID), core.DeviceID(member.ID), input)
		if err != nil {
			t.Fatal(err)
		}
		input[0].Address = "127.0.0.1:5678"
		saved.Candidates[0].Address = "127.0.0.1:9999"
		got, _ := s.GetCandidates(core.NetworkID(n.ID), core.DeviceID(member.ID))
		if got.Candidates[0].Address != "127.0.0.1:1234" {
			t.Error("candidate result changed stored candidates")
		}
	})
	t.Run("diagnostics", func(t *testing.T) {
		input := DiagnosticReport{NetworkID: core.NetworkID(n.ID), DeviceID: core.DeviceID(member.ID), Checks: []DiagnosticCheck{{Name: "probe", Status: "pass", Detail: "original"}}}
		saved, err := s.SaveDiagnostics(input)
		if err != nil {
			t.Fatal(err)
		}
		input.Checks[0].Detail = "input changed"
		got, _ := s.ListDiagnostics(input.NetworkID, input.DeviceID)
		if got[0].Checks[0].Detail != "original" {
			t.Error("diagnostics input changed stored report")
		}
		saved.Checks[0].Detail = "result changed"
		got, _ = s.ListDiagnostics(input.NetworkID, input.DeviceID)
		if got[0].Checks[0].Detail != "original" {
			t.Error("diagnostics result changed stored report")
		}
		got[0].Checks[0].Detail = "listing changed"
		again, _ := s.ListDiagnostics(input.NetworkID, input.DeviceID)
		if again[0].Checks[0].Detail != "original" {
			t.Error("diagnostics listing changed stored report")
		}
	})
}
