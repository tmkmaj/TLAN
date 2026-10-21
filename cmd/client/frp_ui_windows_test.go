//go:build windows

package main

import (
	"strings"
	"testing"
)

func TestParseHeaderLines(t *testing.T) {
	headers, err := parseHeaderLines("X-From: tlan\r\nX-Value: a:b\r\n")
	if err != nil {
		t.Fatal(err)
	}
	if headers["X-From"] != "tlan" || headers["X-Value"] != "a:b" {
		t.Fatalf("parsed headers = %#v", headers)
	}
	if _, err = parseHeaderLines("invalid header"); err == nil {
		t.Fatal("invalid header line accepted")
	}
}

func TestFormatHeaderLinesIsDeterministic(t *testing.T) {
	got := formatHeaderLines(map[string]string{"X-Z": "z", "X-A": "a"})
	if got != "X-A: a\r\nX-Z: z" {
		t.Fatalf("formatted headers = %q", got)
	}
	if !strings.Contains(got, "X-A") || !strings.Contains(got, "X-Z") {
		t.Fatalf("formatted headers lost fields: %q", got)
	}
}

func TestSplitAllowUsersInput(t *testing.T) {
	got := splitDomains("peer-a, peer-b\r\npeer-c")
	if strings.Join(got, ",") != "peer-a,peer-b,peer-c" {
		t.Fatalf("split allow users = %#v", got)
	}
}
