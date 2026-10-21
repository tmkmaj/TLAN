// Package winproc creates Windows processes with an explicitly restricted
// token and verifies the resulting child token before the process is resumed.
package winproc

const EvidenceSchemaVersion = 1

// Evidence records token facts read back from the suspended child process.
// It is intentionally flat so it can be persisted in the FRP runtime ledger.
type Evidence struct {
	SchemaVersion           int    `json:"schemaVersion"`
	TokenSource             string `json:"tokenSource"`
	UserSID                 string `json:"userSid"`
	SessionID               uint32 `json:"sessionId"`
	LogonSession            string `json:"logonSession"`
	ParentUserSID           string `json:"parentUserSid"`
	ParentSessionID         uint32 `json:"parentSessionId"`
	ParentLogonSession      string `json:"parentLogonSession"`
	ParentIntegrityRID      uint32 `json:"parentIntegrityRid"`
	ParentIntegrityLevel    string `json:"parentIntegrityLevel"`
	ParentEnabledPrivileges uint32 `json:"parentEnabledPrivileges"`
	IntegrityRID            uint32 `json:"integrityRid"`
	IntegrityLevel          string `json:"integrityLevel"`
	TokenType               uint32 `json:"tokenType"`
	HasRestrictedSIDs       bool   `json:"hasRestrictedSids"`
	// TokenElevationFlag is the Windows TokenElevation flag. SAFER limited
	// tokens can report true while the Administrators group is deny-only and
	// integrity/privileges are restricted, so callers must not use it alone.
	TokenElevationFlag    bool     `json:"tokenElevationFlag"`
	AdminGroup            string   `json:"adminGroup"`
	EnabledPrivilegeCount uint32   `json:"enabledPrivilegeCount"`
	EnabledPrivileges     []string `json:"enabledPrivileges"`
	GroupSIDs             []string `json:"groupSids"`
}
