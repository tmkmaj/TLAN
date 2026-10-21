package clientapi

import "github.com/private-radminlan/lanmesh/core"

// UploadDiagnostics preserves every check while respecting the existing
// server's 64-check report limit. Stop on failure so callers do not report a
// partially uploaded diagnostic run as successful.
func (c *Client) UploadDiagnostics(networkID core.NetworkID, deviceID core.DeviceID, checks []DiagnosticCheck) error {
	if len(checks) == 0 {
		_, err := c.SubmitDiagnostics(networkID, deviceID, checks)
		return err
	}
	for len(checks) > 0 {
		size := min(64, len(checks))
		if _, err := c.SubmitDiagnostics(networkID, deviceID, checks[:size]); err != nil {
			return err
		}
		checks = checks[size:]
	}
	return nil
}
