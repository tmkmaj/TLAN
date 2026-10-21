package clientapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/private-radminlan/lanmesh/internal/frpauth"
)

func TestClientRetainsHTTPStatus(t *testing.T) {
	for _, status := range []int{401, 403, 404, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "same message"})
			}))
			defer server.Close()
			_, err := New(server.URL, "member_test").Session()
			var response *HTTPError
			if !errors.As(err, &response) || response.StatusCode != status || err.Error() != "server error: same message" {
				t.Fatalf("error = %#v", err)
			}
		})
	}
}

func TestClientUsesControlAPIContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Admin-Token"); got != "test-token" {
			t.Errorf("admin token = %q", got)
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/networks":
			_ = json.NewEncoder(w).Encode(map[string]any{"networks": []Network{{ID: "net-1", Name: "Private", CIDR: "10.240.0.0/24"}}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/networks":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode create request: %v", err)
			}
			if body["name"] != "Private" || body["password"] != "network-password" || body["cidr"] != "10.240.0.0/24" {
				t.Errorf("create request body = %#v", body)
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(Network{ID: "net-1", Name: body["name"], CIDR: body["cidr"]})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/networks/net-1/join":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode join request: %v", err)
			}
			if body["name"] != "Desktop" || body["password"] != "network-password" {
				t.Errorf("join request body = %#v", body)
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(Device{ID: "dev-1", Name: body["name"], VirtualIP: "10.240.0.1"})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := New(server.URL+"/", "test-token")
	networks, err := client.ListNetworks()
	if err != nil || len(networks) != 1 || networks[0].ID != "net-1" {
		t.Fatalf("ListNetworks = %+v, %v", networks, err)
	}
	created, err := client.CreateNetwork("Private", "network-password", "10.240.0.0/24")
	if err != nil || created.ID != "net-1" {
		t.Fatalf("CreateNetwork = %+v, %v", created, err)
	}
	joined, err := client.JoinNetwork("net-1", "Desktop", "network-password")
	if err != nil || joined.VirtualIP != "10.240.0.1" {
		t.Fatalf("JoinNetwork = %+v, %v", joined, err)
	}
}

func TestClientFRPServiceApprovalContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/frp/services/requests":
			var body struct {
				TargetDeviceID string `json:"target_device_id"`
				ServiceID      string `json:"service_id"`
				Protocol       string `json:"protocol"`
				Port           int    `json:"port"`
				TTLSeconds     int    `json:"ttl_seconds"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode request: %v", err)
			}
			if body.TargetDeviceID != "dev-target" || body.ServiceID != "svc-test" || body.Protocol != "tcp" || body.Port != 8080 || body.TTLSeconds != 3600 {
				t.Errorf("request body = %+v", body)
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(frpauth.ServiceResponse{ID: body.ServiceID, ApprovalStatus: frpauth.ServiceApprovalPending})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/frp/services/pending":
			_ = json.NewEncoder(w).Encode(map[string]any{"services": []frpauth.ServiceResponse{{ID: "svc-test", ApprovalStatus: frpauth.ServiceApprovalPending}}})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/frp/services/requested":
			_ = json.NewEncoder(w).Encode(map[string]any{"services": []frpauth.ServiceResponse{{ID: "svc-test", ApprovalStatus: frpauth.ServiceApprovalApproved}}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/frp/services/svc-test/approve":
			_ = json.NewEncoder(w).Encode(frpauth.ServiceResponse{ID: "svc-test", ApprovalStatus: frpauth.ServiceApprovalApproved})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/frp/services/svc-test/deny":
			_ = json.NewEncoder(w).Encode(frpauth.ServiceResponse{ID: "svc-test", ApprovalStatus: frpauth.ServiceApprovalDenied})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/frp/services/svc-test/revoke":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := New(server.URL, "member-token")
	requested, err := client.RequestFRPService("dev-target", "svc-test", "tcp", 8080, "", time.Hour)
	if err != nil || requested.ApprovalStatus != frpauth.ServiceApprovalPending {
		t.Fatalf("RequestFRPService = %+v, %v", requested, err)
	}
	pending, err := client.ListPendingFRPServices()
	if err != nil || len(pending) != 1 {
		t.Fatalf("ListPendingFRPServices = %+v, %v", pending, err)
	}
	requestedServices, err := client.ListRequestedFRPServices()
	if err != nil || len(requestedServices) != 1 || requestedServices[0].ApprovalStatus != frpauth.ServiceApprovalApproved {
		t.Fatalf("ListRequestedFRPServices = %+v, %v", requestedServices, err)
	}
	approved, err := client.ApproveFRPService("svc-test")
	if err != nil || approved.ApprovalStatus != frpauth.ServiceApprovalApproved {
		t.Fatalf("ApproveFRPService = %+v, %v", approved, err)
	}
	denied, err := client.DenyFRPService("svc-test")
	if err != nil || denied.ApprovalStatus != frpauth.ServiceApprovalDenied {
		t.Fatalf("DenyFRPService = %+v, %v", denied, err)
	}
	if err = client.RevokeFRPServiceApproval("svc-test"); err != nil {
		t.Fatalf("RevokeFRPServiceApproval: %v", err)
	}
}
