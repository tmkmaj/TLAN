package platform

import (
	"errors"
	"io"
	"sync"
)

var ErrAdapterUnavailable = errors.New("platform adapter is not available in this build")

// Adapter is the narrow boundary between the portable bridge and an OS layer.
// Implementations must enforce the configured MTU and return complete frames.
type Adapter interface {
	Name() string
	MTU() int
	ReadFrame() ([]byte, error)
	WriteFrame([]byte) error
	Close() error
}

type MemoryAdapter struct {
	name   string
	mtu    int
	in     chan []byte
	out    chan []byte
	closed chan struct{}
	once   sync.Once
}

func NewMemoryAdapter(name string, mtu, queue int) *MemoryAdapter {
	if mtu <= 0 {
		mtu = 1500
	}
	if queue <= 0 {
		queue = 64
	}
	return &MemoryAdapter{name: name, mtu: mtu, in: make(chan []byte, queue), out: make(chan []byte, queue), closed: make(chan struct{})}
}
func (a *MemoryAdapter) Name() string { return a.name }
func (a *MemoryAdapter) MTU() int     { return a.mtu }
func (a *MemoryAdapter) ReadFrame() ([]byte, error) {
	select {
	case <-a.closed:
		return nil, io.ErrClosedPipe
	case frame := <-a.in:
		return append([]byte(nil), frame...), nil
	}
}
func (a *MemoryAdapter) WriteFrame(frame []byte) error {
	if len(frame) > a.mtu+14 {
		return errors.New("frame exceeds adapter MTU")
	}
	select {
	case <-a.closed:
		return io.ErrClosedPipe
	case a.out <- append([]byte(nil), frame...):
		return nil
	default:
		return errors.New("adapter output queue is full")
	}
}
func (a *MemoryAdapter) Inject(frame []byte) error {
	select {
	case <-a.closed:
		return io.ErrClosedPipe
	case a.in <- append([]byte(nil), frame...):
		return nil
	default:
		return errors.New("adapter input queue is full")
	}
}
func (a *MemoryAdapter) TakeWritten() ([]byte, error) {
	select {
	case <-a.closed:
		return nil, io.ErrClosedPipe
	case frame := <-a.out:
		return append([]byte(nil), frame...), nil
	}
}
func (a *MemoryAdapter) Close() error {
	a.once.Do(func() { close(a.closed) })
	return nil
}
