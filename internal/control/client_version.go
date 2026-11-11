//go:build !js

package control

import (
	"errors"
	"fmt"
	"strings"

	"github.com/private-radminlan/lanmesh/core"
	"github.com/private-radminlan/lanmesh/internal/coreupdate"
	"github.com/private-radminlan/lanmesh/internal/storage"
)

// clientVersionHeader is the release version a client reports on every request.
// The value is advisory: the gate exists to force upgrades, not to authenticate
// a client, so a client that lies about its version is only choosing to skip an
// upgrade it was asked to perform.
const clientVersionHeader = "X-Client-Version"

var (
	errClientVersionMissing    = errors.New("client version was not reported; update this client")
	errClientVersionUnreadable = errors.New("client version is not a valid release version")
	errClientOutdated          = errors.New("client version is too old; update this client")
)

// clientVersionAllowed reports whether a member may keep using the server. The
// gate is disabled unless the operator configured server.min_client_version.
func (s *Server) clientVersionAllowed(credential storage.MemberCredential) error {
	required := strings.TrimSpace(s.MinClientVersion)
	if required == "" {
		return nil
	}
	reported, _ := s.Store.ClientVersion(core.DeviceID(credential.DeviceID))
	return evaluateClientVersion(required, reported)
}

// evaluateClientVersion decides whether a reported client version clears the
// configured minimum.
//
// An unreported version is treated as outdated: clients that predate this
// feature cannot prove they are current, and letting them through would defeat
// the purpose of the gate. Pre-release builds (betas) are exempt, which keeps
// the release gate from mixing with the beta channel.
func evaluateClientVersion(required, reported string) error {
	required = strings.TrimSpace(required)
	if required == "" {
		return nil
	}
	reported = strings.TrimSpace(reported)
	if reported == "" {
		return errClientVersionMissing
	}
	prerelease, err := coreupdate.IsPrerelease(reported)
	if err != nil {
		return fmt.Errorf("%w: %q", errClientVersionUnreadable, reported)
	}
	if prerelease {
		return nil
	}
	comparison, err := coreupdate.CompareVersions(reported, required)
	if err != nil {
		return fmt.Errorf("%w: %q", errClientVersionUnreadable, reported)
	}
	if comparison < 0 {
		return fmt.Errorf("%w: running %s, this server requires %s", errClientOutdated, reported, required)
	}
	return nil
}
