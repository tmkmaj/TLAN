package frp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type AdminClient struct {
	baseURL  string
	user     string
	password string
	client   *http.Client
}

type ProxyStatus struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Status     string `json:"status"`
	Err        string `json:"err"`
	LocalAddr  string `json:"local_addr"`
	Plugin     string `json:"plugin"`
	RemoteAddr string `json:"remote_addr"`
	Source     string `json:"source,omitempty"`
}

type StatusResponse map[string][]ProxyStatus

func NewAdminClient(port int, user, password string) *AdminClient {
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) {
				return nil, fmt.Errorf("FRP admin client refused non-loopback address %q", address)
			}
			dialer := net.Dialer{Timeout: 2 * time.Second, KeepAlive: 15 * time.Second}
			return dialer.DialContext(ctx, "tcp4", address)
		},
		ForceAttemptHTTP2: false,
	}
	return &AdminClient{
		baseURL:  "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		user:     user,
		password: password,
		client: &http.Client{
			Transport: transport,
			Timeout:   4 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return fmt.Errorf("FRP management API redirect refused")
			},
		},
	}
}

func (c *AdminClient) Status(ctx context.Context) (StatusResponse, error) {
	var status StatusResponse
	if err := c.doJSON(ctx, http.MethodGet, "/api/status", &status); err != nil {
		return nil, err
	}
	return status, nil
}

func (c *AdminClient) Stop(ctx context.Context) error {
	return c.doJSON(ctx, http.MethodPost, "/api/stop", nil)
}

func (c *AdminClient) Reload(ctx context.Context, strict bool) error {
	path := "/api/reload"
	if strict {
		path += "?strictConfig=true"
	}
	return c.doJSON(ctx, http.MethodGet, path, nil)
}

func (c *AdminClient) doJSON(ctx context.Context, method, path string, output any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.user, c.password)
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("FRP management API unavailable: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024+1))
	if err != nil {
		return fmt.Errorf("read FRP management API response: %w", err)
	}
	if len(body) > 1024*1024 {
		return fmt.Errorf("FRP management API response is too large")
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return codedError(CodeAdminUnauthorized, "FRP management API rejected its per-instance credentials")
	}
	if resp.StatusCode != http.StatusOK {
		message := strings.TrimSpace(string(body))
		if message == "" {
			message = http.StatusText(resp.StatusCode)
		}
		return fmt.Errorf("FRP management API status %d: %s", resp.StatusCode, message)
	}
	if output == nil {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(output); err != nil {
		return fmt.Errorf("decode FRP management API response: %w", err)
	}
	return nil
}
