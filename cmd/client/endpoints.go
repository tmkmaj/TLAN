package main

import (
	"strings"

	"github.com/private-radminlan/lanmesh/internal/clientidentity"
)

const defaultServerURL = "https://8.163.21.82:8443"

// Public deployment settings, never administrator credentials. These variables
// remain overridable with the existing build script's -ldflags options.
var bundledServerURL = defaultServerURL
var bundledSTUNAddress = "8.163.21.82:3478"

// Only the known deployment transition may carry credentials to another URL.
// Developer overrides and unrelated servers must never inherit saved tokens.
// Persistence still happens after a successful, TLS-verified Session response.
func migrateBundledSettings(settings clientidentity.Settings, base string) clientidentity.Settings {
	if base != defaultServerURL {
		return settings
	}
	switch strings.TrimRight(settings.ServerURL, "/") {
	case "https://relay.tmknetwork.online", "https://relay.tmknetwork.online:8443":
		settings.ServerURL = defaultServerURL
		if settings.STUNServer == "relay.tmknetwork.online:3478" {
			settings.STUNServer = bundledSTUNAddress
		}
	}
	return settings
}
