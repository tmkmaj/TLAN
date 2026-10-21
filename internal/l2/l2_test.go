package l2

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

func mustMAC(t *testing.T, value string) MAC {
	t.Helper()
	mac, err := ParseMAC(value)
	if err != nil {
		t.Fatal(err)
	}
	return mac
}

func TestFrameRoundTripAndLimits(t *testing.T) {
	frame := Frame{Destination: mustMAC(t, "02:00:00:00:00:02"), Source: mustMAC(t, "02:00:00:00:00:01"), EtherType: EtherTypeIPv4, Payload: []byte{1, 2, 3}}
	raw, err := frame.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseFrame(raw, DefaultMaxFrame)
	if err != nil || parsed.Source != frame.Source || parsed.Destination != frame.Destination {
		t.Fatalf("round trip failed: %+v %v", parsed, err)
	}
	if _, err := ParseFrame(raw[:10], DefaultMaxFrame); !errors.Is(err, ErrFrameTooShort) {
		t.Fatalf("short frame error = %v", err)
	}
}

func TestARPRequestRoundTrip(t *testing.T) {
	source := mustMAC(t, "02:00:00:00:00:01")
	arpreq := ARP{Operation: ARPRequest, SenderMAC: source, SenderIP: netip.MustParseAddr("10.0.0.1"), TargetIP: netip.MustParseAddr("10.0.0.2")}
	payload, err := arpreq.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseARP(payload)
	if err != nil || parsed.Operation != ARPRequest || parsed.SenderIP != arpreq.SenderIP {
		t.Fatalf("ARP round trip failed: %+v %v", parsed, err)
	}
}

func TestBridgeRejectsSpoofedIPAndControlsBroadcast(t *testing.T) {
	aMAC := mustMAC(t, "02:00:00:00:00:01")
	bMAC := mustMAC(t, "02:00:00:00:00:02")
	bridge, err := NewBridge(DefaultMaxFrame, BroadcastPolicy{Mode: BroadcastAllMembers, MaxFanout: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := bridge.Register(Endpoint{DeviceID: "a", MAC: aMAC, IP: netip.MustParseAddr("10.0.0.1")}); err != nil {
		t.Fatal(err)
	}
	if err := bridge.Register(Endpoint{DeviceID: "b", MAC: bMAC, IP: netip.MustParseAddr("10.0.0.2")}); err != nil {
		t.Fatal(err)
	}
	ipPayload := make([]byte, 20)
	ipPayload[0] = 0x45
	binary.BigEndian.PutUint16(ipPayload[2:4], 20)
	ip := netip.MustParseAddr("10.0.0.99").As4()
	copy(ipPayload[12:16], ip[:])
	frame := Frame{Destination: bMAC, Source: aMAC, EtherType: EtherTypeIPv4, Payload: ipPayload}
	raw, _ := frame.MarshalBinary()
	if _, err := bridge.Route("a", raw); !errors.Is(err, ErrIPMACMismatch) {
		t.Fatalf("spoofed IP error = %v", err)
	}
	ipPayload[12], ipPayload[13], ipPayload[14], ipPayload[15] = 10, 0, 0, 1
	frame.Destination = MAC{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	raw, _ = frame.MarshalBinary()
	deliveries, err := bridge.Route("a", raw)
	if err != nil || len(deliveries) != 1 || deliveries[0].DeviceID != "b" {
		t.Fatalf("broadcast delivery = %+v, %v", deliveries, err)
	}
}

func TestBridgeRejectsDuplicateIPAndDisabledBroadcast(t *testing.T) {
	aMAC := mustMAC(t, "02:00:00:00:00:01")
	bMAC := mustMAC(t, "02:00:00:00:00:02")
	bridge, err := NewBridge(DefaultMaxFrame, BroadcastPolicy{Mode: BroadcastDisabled})
	if err != nil {
		t.Fatal(err)
	}
	if err := bridge.Register(Endpoint{DeviceID: "a", MAC: aMAC, IP: netip.MustParseAddr("10.0.0.1")}); err != nil {
		t.Fatal(err)
	}
	if err := bridge.Register(Endpoint{DeviceID: "b", MAC: bMAC, IP: netip.MustParseAddr("10.0.0.1")}); err == nil {
		t.Fatal("duplicate IP accepted")
	}
	ipPayload := make([]byte, 20)
	ipPayload[0] = 0x45
	binary.BigEndian.PutUint16(ipPayload[2:4], 20)
	ipPayload[12], ipPayload[13], ipPayload[14], ipPayload[15] = 10, 0, 0, 1
	frame := Frame{Destination: MAC{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, Source: aMAC, EtherType: EtherTypeIPv4, Payload: ipPayload}
	raw, _ := frame.MarshalBinary()
	if _, err := bridge.Route("a", raw); !errors.Is(err, ErrBroadcastBlocked) {
		t.Fatalf("broadcast error = %v", err)
	}
}
