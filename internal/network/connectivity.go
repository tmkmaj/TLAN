package network

import (
	"context"
	"errors"
	"sort"

	"github.com/private-radminlan/lanmesh/core"
)

// CandidatePair is a pair considered by a connection adapter. The network
// package only ranks and validates pairs; dialing belongs to the platform
// transport implementation.
type CandidatePair struct {
	Local  core.Candidate
	Remote core.Candidate
	Score  int
}

type ConnectionPlan struct {
	Pairs []CandidatePair
}

// BuildConnectionPlan prioritizes direct UDP, direct TCP, then Relay. A relay
// candidate must carry its server-issued ticket, so an untrusted caller cannot
// smuggle an arbitrary endpoint into a plan.
func BuildConnectionPlan(local, remote []core.Candidate) (ConnectionPlan, error) {
	if len(local) == 0 || len(remote) == 0 {
		return ConnectionPlan{}, errors.New("both candidate sets are required")
	}
	result := make([]CandidatePair, 0, len(local)*len(remote))
	for _, left := range local {
		if err := left.Validate(); err != nil {
			return ConnectionPlan{}, err
		}
		for _, right := range remote {
			if err := right.Validate(); err != nil {
				return ConnectionPlan{}, err
			}
			// Relay pairing is only meaningful when both endpoints advertise the
			// same transport. Direct pairs use the same transport as well.
			if left.Transport != right.Transport {
				continue
			}
			result = append(result, CandidatePair{Local: left, Remote: right, Score: pairScore(left, right)})
		}
	}
	if len(result) == 0 {
		return ConnectionPlan{}, errors.New("no compatible candidate pair")
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Score != result[j].Score {
			return result[i].Score > result[j].Score
		}
		if result[i].Local.Priority != result[j].Local.Priority {
			return result[i].Local.Priority > result[j].Local.Priority
		}
		return result[i].Remote.Priority > result[j].Remote.Priority
	})
	return ConnectionPlan{Pairs: result}, nil
}

func pairScore(local, remote core.Candidate) int {
	score := 0
	if local.Kind != core.CandidateRelay && remote.Kind != core.CandidateRelay {
		score += 1000
	}
	if local.Transport == core.TransportUDP {
		score += 100
	}
	if local.Kind == core.CandidateServerReflexive {
		score += 25
	}
	if local.Kind == core.CandidateHost && remote.Kind == core.CandidateHost {
		score += 20
	}
	if local.Kind == core.CandidateRelay || remote.Kind == core.CandidateRelay {
		score -= 100
	}
	return score
}

// CandidateGatherer is implemented by a platform adapter (for example a
// STUN/ICE client). It is kept small so the core can be tested without sockets.
type CandidateGatherer interface {
	GatherCandidates() ([]core.Candidate, error)
}

// NATType is intentionally descriptive rather than prescriptive. A STUN/ICE
// adapter can report what it observed and the client can use that information
// for diagnostics without changing the control protocol.
type NATType string

const (
	NATUnknown    NATType = "unknown"
	NATOpen       NATType = "open"
	NATFullCone   NATType = "full_cone"
	NATRestricted NATType = "restricted"
	NATSymmetric  NATType = "symmetric"
)

type STUNResult struct {
	ServerAddress string
	MappedAddress string
	NAT           NATType
	SupportsUDP   bool
}

// STUNClient is implemented by a real STUN probe (for example coturn or a
// Pion based client). No STUN dependency is pulled into this package.
type STUNClient interface {
	Probe(context.Context, string) (STUNResult, error)
}

// RelayDialer is the equivalent adapter boundary for a server Relay.
type RelayDialer interface {
	DialRelay(ticket string, transport core.Transport) (RelayChannel, error)
}

type RelayChannel interface {
	Send([]byte) error
	ReceivePacket() ([]byte, error)
	Close() error
}
