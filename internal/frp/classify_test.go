package frp

import "testing"

func TestClassifyStartupError(t *testing.T) {
	cases := map[string]string{
		"certificate signed by unknown authority":    CodeTLSUntrusted,
		"login failed: invalid token":                CodeAuthRejected,
		"remote port 30001 not allowed":              CodeRemotePortDenied,
		"port already used":                          CodeRemotePortBusy,
		"port unavailable":                           CodeRemotePortBusy,
		"remote_port is already leased for this tcp": CodeRemotePortBusy,
		"dial tcp 127.0.0.1:7777: connectex refused": CodeBackendUnreachable,
		"dial tcp 1.2.3.4:7000: connectex timeout":   CodeServerUnreachable,
	}
	for message, want := range cases {
		if got := ErrorCode(classifyStartupError(message)); got != want {
			t.Errorf("%q => %s, want %s", message, got, want)
		}
	}
}

func TestClassifyProxyError(t *testing.T) {
	cases := map[string]string{
		"start error: port unavailable":                          CodeRemotePortBusy,
		"listen tcp 0.0.0.0:60001: bind: address already in use": CodeRemotePortBusy,
		"proxy [tcp_test] already exists":                        CodeRemotePortBusy,
		"remote_port is already leased for this protocol":        CodeRemotePortBusy,
		"port 65000 not in allowed ranges":                       CodeRemotePortDenied,
	}
	for message, want := range cases {
		if got := ErrorCode(classifyProxyError(message)); got != want {
			t.Errorf("classifyProxyError(%q) => %s, want %s", message, got, want)
		}
	}
}
