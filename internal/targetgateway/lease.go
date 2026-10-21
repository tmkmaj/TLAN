package targetgateway

import (
	"context"
	"fmt"
	"sync"
	"time"
)

func acquireLease(ctx context.Context, validator LeaseValidator, target Target) (Lease, error) {
	if err := ctx.Err(); err != nil {
		return Lease{}, err
	}
	lease, err := validator.Validate(ctx, target)
	if err != nil {
		return Lease{}, err
	}
	if err := validateLease(lease); err != nil {
		return Lease{}, err
	}
	return lease, nil
}

func validateLease(lease Lease) error {
	if lease.Generation == 0 {
		return fmt.Errorf("%w: generation is zero", ErrLeaseUnavailable)
	}
	if lease.Done == nil {
		return fmt.Errorf("%w: revocation channel is missing", ErrLeaseUnavailable)
	}
	select {
	case <-lease.Done:
		return ErrLeaseRevoked
	default:
		return nil
	}
}

// leaseGuard pins one generation for one TCP connection or UDP session. Every
// data forwarding step revalidates through the adapter, while watch closes the
// guard immediately when Done is signaled.
type leaseGuard struct {
	validator  LeaseValidator
	target     Target
	generation uint64
	poll       time.Duration

	checkMu sync.Mutex

	mu        sync.Mutex
	done      <-chan struct{}
	err       error
	invalid   chan struct{}
	watchDone chan struct{}
	once      sync.Once
}

func newLeaseGuard(validator LeaseValidator, target Target, initial Lease, poll time.Duration) *leaseGuard {
	return &leaseGuard{
		validator:  validator,
		target:     target,
		generation: initial.Generation,
		poll:       poll,
		done:       initial.Done,
		invalid:    make(chan struct{}),
		watchDone:  make(chan struct{}),
	}
}

func (g *leaseGuard) check(ctx context.Context) error {
	g.checkMu.Lock()
	defer g.checkMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	lease, err := g.validator.Validate(ctx, g.target)
	if err != nil {
		return err
	}
	if err := validateLease(lease); err != nil {
		return err
	}
	if lease.Generation != g.generation {
		return fmt.Errorf("%w: expected %d, got %d", ErrLeaseChanged, g.generation, lease.Generation)
	}
	g.mu.Lock()
	g.done = lease.Done
	g.mu.Unlock()
	return nil
}

func (g *leaseGuard) watch(ctx context.Context) {
	defer close(g.watchDone)
	ticker := time.NewTicker(g.poll)
	defer ticker.Stop()
	for {
		g.mu.Lock()
		done := g.done
		g.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-done:
			g.invalidate(ErrLeaseRevoked)
			return
		case <-ticker.C:
			if err := g.check(ctx); err != nil {
				g.invalidate(err)
				return
			}
		}
	}
}

func (g *leaseGuard) invalidate(err error) {
	g.once.Do(func() {
		g.mu.Lock()
		g.err = err
		g.mu.Unlock()
		close(g.invalid)
	})
}

func (g *leaseGuard) Invalid() <-chan struct{} { return g.invalid }

func (g *leaseGuard) wait() { <-g.watchDone }

func (g *leaseGuard) Err() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.err
}
