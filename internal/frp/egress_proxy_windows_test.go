//go:build windows

package frp

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestEgressProxyAuthenticatedConnect(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	cfg := testConfig(t)
	cfg.Profile.Server.Host = "127.0.0.1"
	cfg.Profile.Server.Port = port
	proxy, err := startEgressProxy(context.Background(), nil, cfg, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp", proxyURL.Host, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	auth := base64.StdEncoding.EncodeToString([]byte(proxy.username + ":" + proxy.password))
	_, _ = fmt.Fprintf(conn, "CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nProxy-Authorization: Basic %s\r\n\r\n", port, port, auth)
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("CONNECT status = %q", status)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	if _, err = io.WriteString(conn, "tlan-proxy-check"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("tlan-proxy-check"))
	if _, err = io.ReadFull(reader, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "tlan-proxy-check" {
		t.Fatalf("echo = %q", buf)
	}
}

func TestEgressProxyRejectsOtherTargets(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Server.Host = "frps.example.test"
	cfg.Profile.Server.Port = 7000
	proxy, err := startEgressProxy(context.Background(), nil, cfg, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if proxy.targetAllowed("other.example.test:7000") {
		t.Fatal("proxy accepted an unconfigured target")
	}
	if !proxy.targetAllowed("FRPS.EXAMPLE.TEST:7000") {
		t.Fatal("proxy rejected case-insensitive configured target")
	}
	if proxy.targetAllowed("frps.example.test:7001") {
		t.Fatal("proxy accepted an unconfigured port")
	}
}
