package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"unicode"
)

const (
	minLeaseTokenBytes = 32
	maxLeaseTokenBytes = 4096
)

type leaseEndpoint struct {
	Scheme string
	Addr   string
}

func resolveLeaseEndpoint(raw string) (leaseEndpoint, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return leaseEndpoint{Scheme: "http", Addr: "127.0.0.1:0"}, nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return leaseEndpoint{}, fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" {
		return leaseEndpoint{}, errors.New("URL must not contain credentials, query parameters, fragments, or opaque data")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return leaseEndpoint{}, errors.New("URL path must be empty or '/'")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return leaseEndpoint{}, errors.New("scheme must be http or https")
	}
	host := parsed.Hostname()
	if host == "" {
		return leaseEndpoint{}, errors.New("host is required")
	}
	portText := parsed.Port()
	if portText == "" {
		if scheme == "https" {
			portText = "443"
		} else {
			portText = "80"
		}
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return leaseEndpoint{}, errors.New("port must be between 0 and 65535")
	}

	if scheme == "http" {
		addr, err := netip.ParseAddr(host)
		if err != nil || !addr.IsLoopback() {
			return leaseEndpoint{}, errors.New("http lease URLs must bind to an IP loopback address")
		}
	} else {
		if host == "*" {
			return leaseEndpoint{}, errors.New("https lease URL must not use a wildcard host")
		}
		if addr, err := netip.ParseAddr(host); err == nil && addr.IsUnspecified() {
			return leaseEndpoint{}, errors.New("https lease URL must not bind an unspecified address")
		}
	}
	return leaseEndpoint{Scheme: scheme, Addr: net.JoinHostPort(host, strconv.Itoa(port))}, nil
}

type bearerAuthenticator struct {
	expected [sha256.Size]byte
	deviceID string
}

func loadBearerAuthenticator(path string) (*bearerAuthenticator, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open lease secret file: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat lease secret file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("lease secret file must be a regular file")
	}
	if err := validateSecretFileMode(info); err != nil {
		return nil, err
	}
	if info.Size() > maxLeaseTokenBytes {
		return nil, fmt.Errorf("lease secret file exceeds %d bytes", maxLeaseTokenBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxLeaseTokenBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read lease secret file: %w", err)
	}
	if len(data) > maxLeaseTokenBytes {
		return nil, fmt.Errorf("lease secret file exceeds %d bytes", maxLeaseTokenBytes)
	}
	token := strings.TrimSpace(string(data))
	if len(token) < minLeaseTokenBytes {
		return nil, fmt.Errorf("lease token must be at least %d bytes", minLeaseTokenBytes)
	}
	if strings.IndexFunc(token, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) >= 0 {
		return nil, errors.New("lease token must not contain whitespace or control characters")
	}
	return newBearerAuthenticator(token), nil
}

func validateSecretFileMode(info os.FileInfo) error {
	if runtime.GOOS == "windows" {
		// Windows does not expose Unix permission bits consistently. The
		// production target is Linux, where the exact mode is enforced below.
		return nil
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("lease secret file mode must be 0600, got %04o", info.Mode().Perm())
	}
	return nil
}

func newBearerAuthenticator(token string) *bearerAuthenticator {
	sum := sha256.Sum256([]byte(token))
	return &bearerAuthenticator{
		expected: sum,
		deviceID: "bearer_" + hex.EncodeToString(sum[:16]),
	}
}

func (a *bearerAuthenticator) Authenticate(request *http.Request) (string, error) {
	if a == nil || request == nil {
		return "", errors.New("bearer authentication is not configured")
	}
	header := strings.TrimSpace(request.Header.Get("Authorization"))
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", errors.New("bearer token is required")
	}
	presented := sha256.Sum256([]byte(parts[1]))
	if subtle.ConstantTimeCompare(presented[:], a.expected[:]) != 1 {
		return "", errors.New("bearer token is invalid")
	}
	return a.deviceID, nil
}

type statusResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusResponseWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(data)
}

type leaseRevocationHandler struct {
	next     http.Handler
	registry *sessionRegistry
}

func (h *leaseRevocationHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	recorder := &statusResponseWriter{ResponseWriter: writer}
	h.next.ServeHTTP(recorder, request)
	status := recorder.status
	if status == 0 {
		status = http.StatusOK
	}
	leaseID, isRevoke := revokeLeaseID(request)
	if isRevoke && request.Method == http.MethodPost && status >= 200 && status < 300 && h.registry != nil {
		h.registry.closeLease(leaseID)
	}
}

func revokeLeaseID(request *http.Request) (string, bool) {
	if request == nil {
		return "", false
	}
	path := strings.TrimSuffix(request.URL.Path, "/")
	const prefix = "/api/v1/egress/leases/"
	if !strings.HasPrefix(path, prefix) {
		return "", false
	}
	parts := strings.Split(strings.TrimPrefix(path, prefix), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] != "revoke" {
		return "", false
	}
	leaseID, err := url.PathUnescape(parts[0])
	if err != nil || leaseID == "" {
		return "", false
	}
	return leaseID, true
}

func validateLeaseBoundAddress(listener net.Listener) error {
	if listener == nil {
		return errors.New("lease listener is not configured")
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || address == nil || address.IP == nil {
		return errors.New("lease listener did not bind a TCP address")
	}
	if address.IP.IsUnspecified() {
		return errors.New("lease listener must not bind an unspecified address")
	}
	return nil
}
