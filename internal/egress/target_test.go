package egress

import (
	"bytes"
	"errors"
	"testing"
)

func TestTargetHeaderRoundTrip(t *testing.T) {
	for _, target := range []OpenTarget{
		{Host: "203.0.113.10", Port: 443, Protocol: ProtocolTCP},
		{Host: "example.com", Port: 53, Protocol: ProtocolUDP},
		{Host: "2001:db8::1", Port: 8443, Protocol: ProtocolTCP},
	} {
		var buffer bytes.Buffer
		if err := WriteTargetPreamble(&buffer, target); err != nil {
			t.Fatalf("write %v: %v", target, err)
		}
		got, err := DecodeTargetHeader(&buffer)
		if err != nil {
			t.Fatalf("decode %v: %v", target, err)
		}
		if got.Host != target.Host || got.Port != target.Port || got.Protocol != target.Protocol {
			t.Fatalf("round trip mismatch: got %+v want %+v", got, target)
		}
	}
}

func TestTargetHeaderRejectsBadInput(t *testing.T) {
	valid := OpenTarget{Host: "example.com", Port: 443, Protocol: ProtocolTCP}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid target rejected: %v", err)
	}
	cases := []OpenTarget{
		{Host: "", Port: 443, Protocol: ProtocolTCP},
		{Host: "exa mple.com", Port: 443, Protocol: ProtocolTCP},
		{Host: "example.com", Port: 0, Protocol: ProtocolTCP},
		{Host: "example.com", Port: 443, Protocol: "icmp"},
	}
	for _, target := range cases {
		if err := target.Validate(); err == nil {
			t.Fatalf("accepted invalid target %+v", target)
		}
	}
	var buffer bytes.Buffer
	if err := WriteTargetPreamble(&buffer, valid); err != nil {
		t.Fatal(err)
	}
	garbage := buffer.Bytes()
	garbage[0] = 9
	if _, err := DecodeTargetHeader(bytes.NewReader(garbage)); err == nil {
		t.Fatal("accepted unknown header version")
	}
}

func TestDatagramEnvelope(t *testing.T) {
	target := OpenTarget{Host: "198.51.100.7", Port: 53, Protocol: ProtocolUDP}
	payload := []byte("dns-payload")
	encoded, err := EncodeDatagram(target, payload)
	if err != nil {
		t.Fatal(err)
	}
	gotTarget, gotPayload, err := DecodeDatagram(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if gotTarget != target || !bytes.Equal(gotPayload, payload) {
		t.Fatalf("datagram mismatch: %+v %q", gotTarget, gotPayload)
	}
	if _, _, err := DecodeDatagram(nil); err == nil {
		t.Fatal("accepted empty datagram")
	}
	header, _ := encodeTargetHeader(target)
	if _, _, err := DecodeDatagram(header); err == nil {
		t.Fatal("accepted datagram without payload")
	}
}

func TestDeriveSessionSecretIsStableAndDistinct(t *testing.T) {
	a := DeriveSessionSecret("capability-a")
	b := DeriveSessionSecret("capability-a")
	c := DeriveSessionSecret("capability-b")
	if !bytes.Equal(a, b) {
		t.Fatal("derivation is not stable")
	}
	if bytes.Equal(a, c) {
		t.Fatal("different capabilities produced the same key")
	}
	if len(a) != 32 {
		t.Fatalf("key length = %d, want 32", len(a))
	}
	if bytes.Equal(a, DeriveHandshakeSecret()) {
		t.Fatal("handshake and session keys must differ")
	}
	if !errors.Is(codedError(CodeInvalidFramePayload, ErrInvalidFramePayload, "x"), ErrInvalidFramePayload) {
		t.Fatal("sanity check failed")
	}
}
