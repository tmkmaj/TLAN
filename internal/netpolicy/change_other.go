//go:build !windows

package netpolicy

// ChangeNotifier is unavailable on non-Windows hosts; callers must keep their
// polling fallback enabled.
type ChangeNotifier interface {
	Changes() <-chan struct{}
	Err() error
	Close() error
}

func NewChangeNotifier() (ChangeNotifier, error) {
	return nil, nil
}
