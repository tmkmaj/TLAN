//go:build !windows

package netpolicy

// NewObserver returns no platform route observer on non-Windows builds. The
// common literal-address check still applies.
func NewObserver() Observer { return nil }
