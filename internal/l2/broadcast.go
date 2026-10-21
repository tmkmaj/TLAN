package l2

import "errors"

type BroadcastMode string

const (
	BroadcastAllMembers      BroadcastMode = "all_members"
	BroadcastSelectedMembers BroadcastMode = "selected_members"
	BroadcastDisabled        BroadcastMode = "disabled"
)

type BroadcastPolicy struct {
	Mode                BroadcastMode
	AllowedDestinations map[MAC]struct{}
	MaxFanout           int
}

func (p BroadcastPolicy) Validate() error {
	if p.Mode != BroadcastAllMembers && p.Mode != BroadcastSelectedMembers && p.Mode != BroadcastDisabled {
		return errors.New("invalid broadcast mode")
	}
	if p.Mode == BroadcastSelectedMembers && len(p.AllowedDestinations) == 0 {
		return errors.New("selected broadcast mode requires destinations")
	}
	if p.MaxFanout < 0 {
		return errors.New("broadcast fanout cannot be negative")
	}
	return nil
}
