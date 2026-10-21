package network

import (
	"errors"
	"net/netip"
	"sort"
	"strings"

	"github.com/private-radminlan/lanmesh/core"
)

type ACLAction uint8

const (
	ACLDefaultDeny ACLAction = iota
	ACLDefaultAllow
)

type PacketInfo struct {
	Source   netip.Addr
	Dest     netip.Addr
	Protocol string
	Port     uint16
}

type compiledRule struct {
	rule       core.ACLRule
	sourceCIDR *netip.Prefix
	destCIDR   *netip.Prefix
}

// ACL evaluates ordered rules. Rules are sorted by Priority and then ID to
// make behavior deterministic even when a caller submits them out of order.
type ACL struct {
	rules        []compiledRule
	defaultAllow bool
}

func NewACL(rules []core.ACLRule, defaultAction ACLAction) (*ACL, error) {
	if defaultAction != ACLDefaultDeny && defaultAction != ACLDefaultAllow {
		return nil, errors.New("invalid ACL default action")
	}
	compiled := make([]compiledRule, 0, len(rules))
	for _, rule := range rules {
		if err := rule.Validate(); err != nil {
			return nil, err
		}
		item := compiledRule{rule: rule}
		if rule.SourceCIDR != "" {
			prefix, _ := netip.ParsePrefix(rule.SourceCIDR)
			prefix = prefix.Masked()
			item.sourceCIDR = &prefix
		}
		if rule.DestCIDR != "" {
			prefix, _ := netip.ParsePrefix(rule.DestCIDR)
			prefix = prefix.Masked()
			item.destCIDR = &prefix
		}
		compiled = append(compiled, item)
	}
	sort.SliceStable(compiled, func(i, j int) bool {
		if compiled[i].rule.Priority != compiled[j].rule.Priority {
			return compiled[i].rule.Priority < compiled[j].rule.Priority
		}
		return compiled[i].rule.ID < compiled[j].rule.ID
	})
	return &ACL{rules: compiled, defaultAllow: defaultAction == ACLDefaultAllow}, nil
}

func (a *ACL) Evaluate(packet PacketInfo) bool {
	if a == nil {
		return false
	}
	for _, item := range a.rules {
		if !item.matches(packet) {
			continue
		}
		return item.rule.Action == "allow"
	}
	return a.defaultAllow
}

func (r compiledRule) matches(packet PacketInfo) bool {
	if r.sourceCIDR != nil && !r.sourceCIDR.Contains(packet.Source) {
		return false
	}
	if r.destCIDR != nil && !r.destCIDR.Contains(packet.Dest) {
		return false
	}
	if r.rule.Protocol != "" && !strings.EqualFold(r.rule.Protocol, packet.Protocol) {
		return false
	}
	if r.rule.FromPort != 0 || r.rule.ToPort != 0 {
		from, to := r.rule.FromPort, r.rule.ToPort
		if from == 0 {
			from = 1
		}
		if to == 0 {
			to = 65535
		}
		if packet.Port < from || packet.Port > to {
			return false
		}
	}
	return true
}
