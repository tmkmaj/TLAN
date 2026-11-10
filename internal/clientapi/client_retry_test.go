package clientapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/private-radminlan/lanmesh/core"
)

func TestClientRetriesGET(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/session" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if attempts.Add(1) < 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "temporary"})
			return
		}
		_ = json.NewEncoder(w).Encode(Membership{})
	}))
	defer server.Close()

	if _, err := New(server.URL, "member_test").Session(); err != nil {
		t.Fatal(err)
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("attempts = %d, want 2", got)
	}
}

func TestClientRetriesHeartbeatPOST(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/devices/dev-1/heartbeat" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if attempts.Add(1) < 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "temporary"})
			return
		}
		_ = json.NewEncoder(w).Encode(RegisteredDevice{Identity: core.DeviceIdentity{DeviceID: "dev-1"}})
	}))
	defer server.Close()

	if _, err := New(server.URL, "member_test").Heartbeat("dev-1"); err != nil {
		t.Fatal(err)
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("attempts = %d, want 2", got)
	}
}

func TestClientDoesNotRetryNonIdempotentPOSTs(t *testing.T) {
	tests := []struct {
		name string
		call func(*Client) error
	}{
		{
			name: "enroll",
			call: func(c *Client) error {
				_, err := c.Enroll("code", core.RegisterDeviceRequest{}, "invalid")
				return err
			},
		},
		{
			name: "relay_session",
			call: func(c *Client) error {
				_, err := c.CreateRelaySession("net-1", "dev-1", "dev-2", 0)
				return err
			},
		},
		{
			name: "frp_lease",
			call: func(c *Client) error {
				_, err := c.CreateFRPLease("net-1", "dev-1", "server-1", nil)
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var attempts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts.Add(1)
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "temporary"})
			}))
			defer server.Close()

			err := test.call(New(server.URL, "member_test"))
			var response *HTTPError
			if !errors.As(err, &response) || response.StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("error = %#v", err)
			}
			if got := attempts.Load(); got != 1 {
				t.Fatalf("attempts = %d, want 1", got)
			}
		})
	}
}

func TestClientDoesNotRetryPermanentHTTPStatuses(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusConflict, http.StatusTooManyRequests} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var attempts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts.Add(1)
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "permanent"})
			}))
			defer server.Close()

			_, err := New(server.URL, "member_test").Session()
			var response *HTTPError
			if !errors.As(err, &response) || response.StatusCode != status {
				t.Fatalf("error = %#v", err)
			}
			if got := attempts.Load(); got != 1 {
				t.Fatalf("attempts = %d, want 1", got)
			}
		})
	}
}
func TestClientRetriesAtMostThreeAttemptsAndKeepsStatus(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "temporary"})
	}))
	defer server.Close()

	_, err := New(server.URL, "member_test").Session()
	var response *HTTPError
	if !errors.As(err, &response) || response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("error = %#v", err)
	}
	if got := attempts.Load(); got != 3 {
		t.Fatalf("attempts = %d, want 3", got)
	}
}

func TestClientCancellationStopsRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		cancel()
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "temporary"})
	}))
	defer server.Close()

	client := New(server.URL, "member_test")
	client.Context = ctx
	_, err := client.Session()
	if err == nil {
		t.Fatal("expected cancellation error")
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("attempts = %d, want 1 (%v)", got, fmt.Errorf("request error: %w", err))
	}
}
