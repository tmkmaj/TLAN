package clientapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestIPHTTPSVerifiesCertificateWithoutDomainSNI(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer member_test" {
			t.Error("missing member credential")
		}
		_, _ = w.Write([]byte(`{"network":{"id":"net-test"}}`))
	}))
	server.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if hello.ServerName != "" {
			t.Errorf("IP connection sent SNI %q", hello.ServerName)
		}
		return nil, nil
	}}
	server.StartTLS()
	defer server.Close()

	if _, err := New(server.URL, "member_test").Session(); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client := New(server.URL, "member_test")
	transport := client.HTTP.Transport.(*http.Transport)
	transport.TLSClientConfig.RootCAs = roots
	defer transport.CloseIdleConnections()
	if m, err := client.Session(); err != nil || m.Network.ID != "net-test" {
		t.Fatalf("IP HTTPS failed: %v", err)
	}

	// Route to the same test server but request another IP identity: trusting
	// the issuer must not bypass the certificate's IP SAN validation.
	address, _ := url.Parse(server.URL)
	other := New("https://192.0.2.1:"+address.Port(), "member_test")
	otherTransport := other.HTTP.Transport.(*http.Transport)
	otherTransport.TLSClientConfig.RootCAs = roots
	otherTransport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address.Host)
	}
	defer otherTransport.CloseIdleConnections()
	if _, err := other.Session(); err == nil {
		t.Fatal("certificate for a different IP accepted")
	}
}
