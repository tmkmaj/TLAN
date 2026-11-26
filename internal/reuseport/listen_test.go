package reuseport

import (
	"net"
	"testing"
)

func TestListenBindsAndAccepts(t *testing.T) {
	listener, err := Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = conn.Close()
		}
		accepted <- acceptErr
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
}

func TestListenRejectsInvalidAddress(t *testing.T) {
	listener, err := Listen("tcp", "not-an-address")
	if listener != nil {
		_ = listener.Close()
	}
	if err == nil {
		t.Fatal("Listen accepted an invalid address")
	}
}

func TestListenReturnsClosableDuplicate(t *testing.T) {
	first, err := Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := Listen("tcp", first.Addr().String())
	if err != nil {
		if Enabled() {
			t.Fatal(err)
		}
		return
	}
	defer second.Close()
	if !Enabled() {
		t.Fatal("fallback unexpectedly allowed duplicate listeners")
	}
}
