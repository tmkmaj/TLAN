//go:build !windows

package platform

import "fmt"

// cleanupResource is deliberately conservative on non-Windows platforms.
// We can prove logical transport ownership, but cannot safely prove and
// remove a pre-existing OS adapter/route from a crashed process here.
func cleanupResource(record ResourceRecord, _ Runner) error {
	switch record.Type {
	case ResourceWireGuardTransport, ResourcePlainTransport:
		return nil
	default:
		return fmt.Errorf("%w: %s %q cannot be removed safely on this platform",
			ErrResourceUnsupported, record.Type, record.Name)
	}
}
