package frp

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestAdminClientStatusAndAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/status" {
			http.NotFound(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != "u" || pass != "p" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, "{\"tcp\":[{\"name\":\"proxy\",\"type\":\"tcp\",\"status\":\"running\",\"err\":\"\",\"local_addr\":\"127.0.0.1:7777\",\"plugin\":\"\",\"remote_addr\":\"127.0.0.1:30001\"}]}")
	}))
	defer server.Close()
	host, portText, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	if host != "127.0.0.1" {
		t.Skip("httptest is not on loopback")
	}
	client := NewAdminClient(port, "u", "p")
	status, err := client.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := status["tcp"][0].RemoteAddr; got != "127.0.0.1:30001" {
		t.Fatalf("remote addr = %q", got)
	}
	bad := NewAdminClient(port, "u", "wrong")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err = bad.Status(ctx); ErrorCode(err) != CodeAdminUnauthorized {
		t.Fatalf("unauthorized error = %v", err)
	}
}
