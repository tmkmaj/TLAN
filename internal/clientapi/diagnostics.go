package clientapi

import (
	"bytes"
	"encoding/json"

	"github.com/private-radminlan/lanmesh/core"
	"github.com/private-radminlan/lanmesh/internal/diagreport"
)

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

// UploadDiagnosticsWithFRP uploads all checks using the legacy 64-check batching
// rule and attaches the complete FRP report to the first batch. If there are no
// checks, the FRP report is submitted by itself. A report is never duplicated
// across batches.
func (c *Client) UploadDiagnosticsWithFRP(networkID core.NetworkID, deviceID core.DeviceID, checks []DiagnosticCheck, frpReport json.RawMessage) error {
	frpReport = bytes.TrimSpace(frpReport)
	if len(frpReport) == 0 {
		return c.UploadDiagnostics(networkID, deviceID, checks)
	}
	sanitized, err := diagreport.Sanitize(frpReport)
	if err != nil {
		return err
	}
	if len(checks) == 0 {
		_, err = c.SubmitDiagnosticsWithFRP(networkID, deviceID, nil, sanitized)
		return err
	}
	size := min(64, len(checks))
	if _, err = c.SubmitDiagnosticsWithFRP(networkID, deviceID, checks[:size], sanitized); err != nil {
		return err
	}
	if len(checks) == size {
		return nil
	}
	return c.UploadDiagnostics(networkID, deviceID, checks[size:])
}
