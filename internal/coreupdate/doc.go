// Package coreupdate provides fail-closed verification and atomic installation
// of Ed25519-signed FRPC core artifacts.
//
// It is infrastructure only: callers must inject a production public key,
// version/platform allowlists, and a core root. It does not contain a
// production key, does not check for updates on its own, and is not wired into
// the desktop client or FRP manager.
package coreupdate
