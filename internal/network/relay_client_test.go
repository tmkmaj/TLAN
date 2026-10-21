package network

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestRelayHandshakeCancellation(t *testing.T) {
	for _, phase := range []string{"upgrade", "ticket"} {
		t.Run(phase, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ready := make(chan struct{})
			serverDone := make(chan struct{})
			go func() {
				defer close(serverDone)
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				reader := bufio.NewReader(conn)
				if _, err := http.ReadRequest(reader); err != nil {
					return
				}
				if phase == "ticket" {
					_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: lanmesh-relay\r\n\r\n")
					if _, err := reader.ReadString('\n'); err != nil {
						return
					}
				}
				close(ready)
				_, _ = io.Copy(io.Discard, reader)
			}()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				relay, err := DialHTTPRelay(ctx, "http://"+listener.Addr().String(), "test", RelayTicket{}, "device-a")
				if relay != nil {
					relay.Close()
				}
				done <- err
			}()
			select {
			case <-ready:
			case <-time.After(2 * time.Second):
				t.Fatal("handshake did not reach stalled phase")
			}
			cancel()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("canceled handshake succeeded")
				}
			case <-time.After(time.Second):
				t.Error("cancellation left handshake blocked")
			}
			<-serverDone
		})
	}
}

func TestSuccessfulRelayOutlivesDialContext(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		reader := bufio.NewReader(conn)
		if _, err := http.ReadRequest(reader); err != nil {
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: lanmesh-relay\r\n\r\n")
		if _, err := reader.ReadString('\n'); err != nil {
			return
		}
		_ = json.NewEncoder(conn).Encode(relayHandshakeResponse{OK: true})
		_, _ = io.Copy(conn, reader)
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	relay, err := DialHTTPRelay(ctx, "http://"+listener.Addr().String(), "test", RelayTicket{}, "device-a")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { relay.Close(); <-serverDone }()
	cancel()
	_ = relay.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if err := relay.Send([]byte("still connected")); err != nil {
		t.Fatal(err)
	}
	packet, err := relay.ReceivePacket()
	if err != nil || string(packet) != "still connected" {
		t.Fatalf("packet = %q, error = %v", packet, err)
	}
}
