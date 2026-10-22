package clientapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/private-radminlan/lanmesh/core"
	"github.com/private-radminlan/lanmesh/internal/diagreport"
	"github.com/private-radminlan/lanmesh/internal/enrollment"
	"github.com/private-radminlan/lanmesh/internal/frpauth"
)

type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
	Context context.Context
}

type Network struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CIDR      string    `json:"cidr"`
	CreatedAt time.Time `json:"created_at"`
	Devices   int       `json:"devices"`
}

type Device struct {
	Forwarding *bool     `json:"forwarding,omitempty"`
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	VirtualIP  string    `json:"virtual_ip"`
	Online     bool      `json:"online"`
	JoinedAt   time.Time `json:"joined_at"`
	PublicKey  string    `json:"public_key,omitempty"`
	LastSeen   time.Time `json:"last_seen"`
}

type Membership struct {
	Network Network `json:"network"`
	Member  Device  `json:"member"`
	Token   string  `json:"token,omitempty"`
}

func (c *Client) Enroll(code string, device core.RegisterDeviceRequest, privateKey string) (Membership, error) {
	var sealed enrollment.Envelope
	if err := c.request(http.MethodPost, "/api/v1/enroll", map[string]any{"code": code, "device": device}, &sealed); err != nil {
		return Membership{}, err
	}
	plain, err := enrollment.Open(privateKey, sealed)
	if err != nil {
		return Membership{}, fmt.Errorf("open enrollment response: %w", err)
	}
	var membership Membership
	if err = json.Unmarshal(plain, &membership); err != nil {
		return Membership{}, err
	}
	if membership.Member.ID != device.DeviceID.String() || membership.Member.PublicKey != device.WireGuardPublicKey || !strings.HasPrefix(membership.Token, "member_") {
		return Membership{}, fmt.Errorf("invalid enrollment identity")
	}
	return membership, nil
}
func (c *Client) Session() (Membership, error) {
	var m Membership
	err := c.request(http.MethodGet, "/api/v1/session", nil, &m)
	return m, err
}
func (c *Client) SetForwarding(nid core.NetworkID, did core.DeviceID, enabled bool) (Device, error) {
	var d Device
	err := c.request(http.MethodPost, "/api/v1/networks/"+nid.String()+"/devices/"+did.String()+"/forwarding", map[string]bool{"enabled": enabled}, &d)
	return d, err
}

type RegisteredDevice struct {
	Identity    core.DeviceIdentity `json:"identity"`
	DisplayName string              `json:"display_name,omitempty"`
	CreatedAt   time.Time           `json:"created_at"`
	LastSeen    time.Time           `json:"last_seen"`
	Online      bool                `json:"online"`
}

type CandidateRecord struct {
	DeviceID   core.DeviceID    `json:"device_id"`
	NetworkID  core.NetworkID   `json:"network_id"`
	Candidates []core.Candidate `json:"candidates"`
	UpdatedAt  time.Time        `json:"updated_at"`
}

type DiagnosticCheck struct {
	Name    string    `json:"name"`
	Status  string    `json:"status"`
	Detail  string    `json:"detail,omitempty"`
	Checked time.Time `json:"checked"`
}

type DiagnosticReport struct {
	DeviceID  core.DeviceID     `json:"device_id"`
	NetworkID core.NetworkID    `json:"network_id"`
	Checks    []DiagnosticCheck `json:"checks"`
	FRPReport json.RawMessage   `json:"frp_report,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

type RelayTicket struct {
	SessionID string        `json:"session_id"`
	Source    core.DeviceID `json:"source"`
	Target    core.DeviceID `json:"target"`
	Secret    string        `json:"secret"`
	ExpiresAt time.Time     `json:"expires_at"`
}

func New(baseURL, token string) *Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// The control API must reach the configured relay directly. Bypass local
	// proxy settings and force HTTP/1.1 so security software cannot reset an
	// HTTP/2 connection during enrollment. The relay protocol is HTTP/1.1 too.
	transport.Proxy = nil
	transport.ForceAttemptHTTP2 = false
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	transport.TLSNextProto = make(map[string]func(string, *tls.Conn) http.RoundTripper)
	return &Client{BaseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"), Token: token, HTTP: &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(request *http.Request, via []*http.Request) error {
		if len(via) >= 5 || request.URL.Host != via[0].URL.Host || (via[0].URL.Scheme == "https" && request.URL.Scheme != "https") {
			return http.ErrUseLastResponse
		}
		return nil
	}}}
}

func (c *Client) ListNetworks() ([]Network, error) {
	var response struct {
		Networks []Network `json:"networks"`
	}
	if err := c.request(http.MethodGet, "/api/v1/networks", nil, &response); err != nil {
		return nil, err
	}
	return response.Networks, nil
}

func (c *Client) CreateNetwork(name, password, cidr string) (Network, error) {
	var response Network
	err := c.request(http.MethodPost, "/api/v1/networks", map[string]string{"name": name, "password": password, "cidr": cidr}, &response)
	return response, err
}

func (c *Client) JoinNetwork(networkID, name, password string) (Device, error) {
	var response Device
	err := c.request(http.MethodPost, "/api/v1/networks/"+networkID+"/join", map[string]string{"name": name, "password": password}, &response)
	return response, err
}

func (c *Client) JoinNetworkAs(networkID core.NetworkID, deviceID core.DeviceID, name, password string) (Device, error) {
	var response Device
	err := c.request(http.MethodPost, "/api/v1/networks/"+networkID.String()+"/join", map[string]string{
		"device_id": deviceID.String(),
		"name":      name,
		"password":  password,
	}, &response)
	return response, err
}

func (c *Client) RegisterDevice(request core.RegisterDeviceRequest) (RegisteredDevice, error) {
	var response RegisteredDevice
	err := c.request(http.MethodPost, "/api/v1/devices/register", request, &response)
	return response, err
}

func (c *Client) ListDevices(networkID core.NetworkID) ([]Device, error) {
	var response struct {
		Devices []Device `json:"devices"`
	}
	err := c.request(http.MethodGet, "/api/v1/networks/"+networkID.String()+"/devices", nil, &response)
	return response.Devices, err
}
func (c *Client) RemoveDevice(networkID core.NetworkID, deviceID core.DeviceID) error {
	return c.request(http.MethodDelete, "/api/v1/networks/"+networkID.String()+"/devices?id="+deviceID.String(), nil, nil)
}

func (c *Client) Heartbeat(deviceID core.DeviceID) (RegisteredDevice, error) {
	var response RegisteredDevice
	err := c.request(http.MethodPost, "/api/v1/devices/"+deviceID.String()+"/heartbeat", nil, &response)
	return response, err
}

func (c *Client) SetCandidates(networkID core.NetworkID, deviceID core.DeviceID, candidates []core.Candidate) (CandidateRecord, error) {
	var response CandidateRecord
	err := c.request(http.MethodPost, "/api/v1/networks/"+networkID.String()+"/devices/"+deviceID.String()+"/candidates", map[string]any{"candidates": candidates}, &response)
	return response, err
}

func (c *Client) GetCandidates(networkID core.NetworkID, deviceID core.DeviceID) (CandidateRecord, error) {
	var response CandidateRecord
	err := c.request(http.MethodGet, "/api/v1/networks/"+networkID.String()+"/devices/"+deviceID.String()+"/candidates", nil, &response)
	return response, err
}

func (c *Client) SubmitDiagnostics(networkID core.NetworkID, deviceID core.DeviceID, checks []DiagnosticCheck) (DiagnosticReport, error) {
	return c.SubmitDiagnosticsWithFRP(networkID, deviceID, checks, nil)
}

// SubmitDiagnosticsWithFRP submits one legacy checks batch together with an
// optional complete FRP diagnostic report. The report is sanitized client-side
// and again by the control plane before it is persisted.
func (c *Client) SubmitDiagnosticsWithFRP(networkID core.NetworkID, deviceID core.DeviceID, checks []DiagnosticCheck, frpReport json.RawMessage) (DiagnosticReport, error) {
	var response DiagnosticReport
	body := map[string]any{"checks": checks}
	if len(frpReport) > 0 {
		sanitized, err := diagreport.Sanitize(frpReport)
		if err != nil {
			return DiagnosticReport{}, err
		}
		body["frp_report"] = sanitized
	}
	err := c.request(http.MethodPost, "/api/v1/networks/"+networkID.String()+"/devices/"+deviceID.String()+"/diagnostics", body, &response)
	return response, err
}

func (c *Client) ListDiagnostics(networkID core.NetworkID, deviceID core.DeviceID) ([]DiagnosticReport, error) {
	var response struct {
		Reports []DiagnosticReport `json:"reports"`
	}
	err := c.request(http.MethodGet, "/api/v1/networks/"+networkID.String()+"/devices/"+deviceID.String()+"/diagnostics", nil, &response)
	return response.Reports, err
}

func (c *Client) CreateRelaySession(networkID core.NetworkID, source, target core.DeviceID, ttl time.Duration) (RelayTicket, error) {
	var response RelayTicket
	body := map[string]any{"network_id": networkID, "source_device_id": source, "target_device_id": target}
	if ttl > 0 {
		body["ttl_seconds"] = int(ttl / time.Second)
	}
	err := c.request(http.MethodPost, "/api/v1/relay/sessions", body, &response)
	return response, err
}

func (c *Client) request(method, path string, body any, target any) error {
	if c == nil || c.BaseURL == "" {
		return fmt.Errorf("server URL is required")
	}
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	ctx := c.Context
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		if strings.HasPrefix(c.Token, "member_") {
			req.Header.Set("Authorization", "Bearer "+c.Token)
		} else {
			req.Header.Set("X-Admin-Token", c.Token)
		}
	}
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("control service unavailable: %w", err)
	}
	defer resp.Body.Close()
	var envelope struct {
		Error string `json:"error"`
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_ = json.NewDecoder(resp.Body).Decode(&envelope)
		if envelope.Error == "" {
			envelope.Error = resp.Status
		}
		return &HTTPError{StatusCode: resp.StatusCode, Message: envelope.Error}
	}
	if target == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		return fmt.Errorf("decode server response: %w", err)
	}
	return nil
}

func (c *Client) CreateFRPLease(networkID, deviceID, serverID string, rules []frpauth.Rule) (frpauth.LeaseResponse, error) {
	var response frpauth.LeaseResponse
	body := struct {
		NetworkID string         `json:"network_id"`
		DeviceID  string         `json:"device_id"`
		ServerID  string         `json:"server_id"`
		Rules     []frpauth.Rule `json:"rules"`
	}{networkID, deviceID, serverID, rules}
	err := c.request(http.MethodPost, "/api/v1/frp/leases", body, &response)
	return response, err
}

func (c *Client) RenewFRPLease(leaseID string) (frpauth.LeaseResponse, error) {
	var response frpauth.LeaseResponse
	err := c.request(http.MethodPost, "/api/v1/frp/leases/"+leaseID+"/renew", nil, &response)
	return response, err
}

func (c *Client) FRPLeaseStatus(leaseID string) (frpauth.LeaseStatus, error) {
	var response frpauth.LeaseStatus
	err := c.request(http.MethodGet, "/api/v1/frp/leases/"+leaseID+"/status", nil, &response)
	return response, err
}

func (c *Client) RevokeFRPLease(leaseID string) error {
	return c.request(http.MethodDelete, "/api/v1/frp/leases/"+leaseID, nil, nil)
}

func (c *Client) ListFRPServices(networkID, deviceID string) ([]frpauth.ServiceResponse, error) {
	var response struct {
		Services []frpauth.ServiceResponse `json:"services"`
	}
	path := "/api/v1/frp/services?network_id=" + networkID + "&device_id=" + deviceID
	if err := c.request(http.MethodGet, path, nil, &response); err != nil {
		return nil, err
	}
	return response.Services, nil
}

func (c *Client) RequestFRPService(targetDeviceID, serviceID, protocol string, port int, description string, ttl time.Duration) (frpauth.ServiceResponse, error) {
	var response frpauth.ServiceResponse
	body := struct {
		TargetDeviceID string `json:"target_device_id"`
		ServiceID      string `json:"service_id,omitempty"`
		Protocol       string `json:"protocol"`
		Port           int    `json:"port"`
		Description    string `json:"description,omitempty"`
		TTLSeconds     int    `json:"ttl_seconds,omitempty"`
	}{
		TargetDeviceID: targetDeviceID, ServiceID: serviceID, Protocol: protocol, Port: port,
		Description: description, TTLSeconds: int(ttl / time.Second),
	}
	err := c.request(http.MethodPost, "/api/v1/frp/services/requests", body, &response)
	return response, err
}

func (c *Client) ListPendingFRPServices() ([]frpauth.ServiceResponse, error) {
	var response struct {
		Services []frpauth.ServiceResponse `json:"services"`
	}
	if err := c.request(http.MethodGet, "/api/v1/frp/services/pending", nil, &response); err != nil {
		return nil, err
	}
	return response.Services, nil
}

func (c *Client) ListRequestedFRPServices() ([]frpauth.ServiceResponse, error) {
	var response struct {
		Services []frpauth.ServiceResponse `json:"services"`
	}
	if err := c.request(http.MethodGet, "/api/v1/frp/services/requested", nil, &response); err != nil {
		return nil, err
	}
	return response.Services, nil
}

func (c *Client) ApproveFRPService(serviceID string) (frpauth.ServiceResponse, error) {
	var response frpauth.ServiceResponse
	err := c.request(http.MethodPost, "/api/v1/frp/services/"+serviceID+"/approve", nil, &response)
	return response, err
}

func (c *Client) DenyFRPService(serviceID string) (frpauth.ServiceResponse, error) {
	var response frpauth.ServiceResponse
	err := c.request(http.MethodPost, "/api/v1/frp/services/"+serviceID+"/deny", nil, &response)
	return response, err
}

func (c *Client) RevokeFRPServiceApproval(serviceID string) error {
	return c.request(http.MethodPost, "/api/v1/frp/services/"+serviceID+"/revoke", nil, nil)
}
